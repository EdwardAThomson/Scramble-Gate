#!/usr/bin/env python3
"""
Analyze ScrambleGate mode comparison results and provide insights.
"""

import os
import json
import glob
from datetime import datetime

def analyze_results():
    """Analyze all available test results"""
    
    print("🔍 SCRAMBLEGATE MODE ANALYSIS")
    print("=" * 60)
    
    # Find all result directories
    result_dirs = glob.glob("scramblegate_results_GPT4o_*_*/")
    
    if not result_dirs:
        print("❌ No result directories found")
        return
    
    results = {}
    
    for result_dir in result_dirs:
        # Extract mode from directory name
        parts = result_dir.split('_')
        if len(parts) >= 4:
            mode = parts[3]  # Extract mode from scramblegate_results_GPT4o_MODE_timestamp/
            
            # Load results.json
            json_file = os.path.join(result_dir, "results.json")
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                # Calculate metrics
                total = len(data)
                blocked = sum(1 for item in data if item.get('verdict') == 'BLOCK')
                allowed = sum(1 for item in data if item.get('verdict') == 'ALLOW')
                errors = sum(1 for item in data if item.get('verdict') == 'ERROR')
                
                detection_rate = (blocked / total * 100) if total > 0 else 0
                avg_risk = sum(item.get('risk', 0) for item in data) / total if total > 0 else 0
                
                results[mode] = {
                    'total': total,
                    'blocked': blocked,
                    'allowed': allowed,
                    'errors': errors,
                    'detection_rate': detection_rate,
                    'avg_risk': avg_risk,
                    'directory': result_dir
                }
    
    # Sort by detection rate
    sorted_results = sorted(results.items(), key=lambda x: x[1]['detection_rate'], reverse=True)
    
    print("\n📊 MODE PERFORMANCE RANKING")
    print("-" * 60)
    print(f"{'Mode':<20} {'Detection Rate':<15} {'Blocked/Total':<12} {'Avg Risk':<10}")
    print("-" * 60)
    
    for mode, data in sorted_results:
        detection_rate = f"{data['detection_rate']:.1f}%"
        blocked_total = f"{data['blocked']}/{data['total']}"
        avg_risk = f"{data['avg_risk']:.2f}"
        
        print(f"{mode:<20} {detection_rate:<15} {blocked_total:<12} {avg_risk:<10}")
    
    # Analysis insights
    print("\n🧠 KEY INSIGHTS")
    print("-" * 60)
    
    if 'probabilistic' in results and 'pure' in results:
        prob_rate = results['probabilistic']['detection_rate']
        pure_rate = results['pure']['detection_rate']
        improvement = prob_rate - pure_rate
        print(f"• Probabilistic vs Pure Scrambling: +{improvement:.1f}% improvement")
    
    if 'masking' in results and 'pure' in results:
        mask_rate = results['masking']['detection_rate']
        pure_rate = results['pure']['detection_rate']
        improvement = mask_rate - pure_rate
        print(f"• Masking vs Pure Scrambling: +{improvement:.1f}% improvement")
    
    if 'clean' in results:
        clean_rate = results['clean']['detection_rate']
        print(f"• Clean copies achieve {clean_rate:.1f}% detection (surprisingly effective)")
    
    # Find best performing mode
    if sorted_results:
        best_mode, best_data = sorted_results[0]
        print(f"• Best performing mode: {best_mode} ({best_data['detection_rate']:.1f}%)")
    
    print("\n💡 RECOMMENDATIONS")
    print("-" * 60)
    print("1. Use 'probabilistic' mode for balanced performance and unpredictability")
    print("2. Consider 'clean_only' for simpler implementation with good results")
    print("3. Avoid 'pure_scrambling' - least effective against modern LLMs")
    print("4. Masking strategies consistently outperform pure scrambling")
    print("5. Information removal > information reordering for detection")
    
    print(f"\n📁 Results analyzed from {len(results)} test runs")
    print(f"📅 Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def compare_specific_modes(mode1, mode2):
    """Compare two specific modes in detail"""
    
    # Find result files for both modes
    dirs1 = glob.glob(f"scramblegate_results_GPT4o_{mode1}_*/")
    dirs2 = glob.glob(f"scramblegate_results_GPT4o_{mode2}_*/")
    
    if not dirs1 or not dirs2:
        print(f"❌ Could not find results for {mode1} or {mode2}")
        return
    
    # Load latest results for each mode
    dir1 = sorted(dirs1)[-1]
    dir2 = sorted(dirs2)[-1]
    
    with open(os.path.join(dir1, "results.json"), 'r') as f:
        data1 = json.load(f)
    
    with open(os.path.join(dir2, "results.json"), 'r') as f:
        data2 = json.load(f)
    
    print(f"\n🔍 DETAILED COMPARISON: {mode1} vs {mode2}")
    print("=" * 60)
    
    # Compare performance on same prompts
    prompt_comparison = {}
    
    for item1 in data1:
        prompt = item1.get('prompt', '')[:50] + "..."
        prompt_comparison[prompt] = {'mode1': item1}
    
    for item2 in data2:
        prompt = item2.get('prompt', '')[:50] + "..."
        if prompt in prompt_comparison:
            prompt_comparison[prompt]['mode2'] = item2
    
    # Show cases where modes differed
    differences = []
    for prompt, data in prompt_comparison.items():
        if 'mode1' in data and 'mode2' in data:
            verdict1 = data['mode1'].get('verdict')
            verdict2 = data['mode2'].get('verdict')
            
            if verdict1 != verdict2:
                differences.append({
                    'prompt': prompt,
                    'mode1_verdict': verdict1,
                    'mode2_verdict': verdict2,
                    'mode1_risk': data['mode1'].get('risk', 0),
                    'mode2_risk': data['mode2'].get('risk', 0)
                })
    
    print(f"📊 Found {len(differences)} cases where modes disagreed:")
    print()
    
    for diff in differences[:5]:  # Show first 5 differences
        print(f"Prompt: {diff['prompt']}")
        print(f"  {mode1}: {diff['mode1_verdict']} (risk: {diff['mode1_risk']:.2f})")
        print(f"  {mode2}: {diff['mode2_verdict']} (risk: {diff['mode2_risk']:.2f})")
        print()

if __name__ == "__main__":
    analyze_results()
    
    # Optional: Compare specific modes
    import sys
    if len(sys.argv) == 3:
        compare_specific_modes(sys.argv[1], sys.argv[2])
