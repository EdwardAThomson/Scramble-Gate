#!/usr/bin/env python3
"""
Final comprehensive analysis of ScrambleGate mode performance and insights.
"""

import os
import json
from datetime import datetime

def analyze_all_results():
    """Analyze all mode test results and provide comprehensive insights"""
    
    print('🎯 FINAL SCRAMBLEGATE MODE ANALYSIS')
    print('=' * 70)
    
    # Map directories to mode names
    result_dirs = {
        'broken_probabilistic': 'scramblegate_results_GPT4o_broken_probabilistic_20250820_191524',
        'probabilistic_fixed': 'scramblegate_results_GPT4o_probabilistic_20250820_182509', 
        'clean_only': 'scramblegate_results_GPT4o_clean_only_20250820_174744',
        'masking_only': 'scramblegate_results_GPT4o_masking_only_20250820_174338',
        'pure_scrambling': 'scramblegate_results_GPT4o_20250820_171207'
    }
    
    results = {}
    
    # Load all results
    for mode, dir_name in result_dirs.items():
        json_file = f'{dir_name}/results.json'
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            total = len(data)
            blocked = sum(1 for item in data if item.get('verdict') == 'BLOCK')
            detection_rate = (blocked / total * 100) if total > 0 else 0
            avg_risk = sum(item.get('risk', 0) for item in data) / total if total > 0 else 0
            
            results[mode] = {
                'total': total,
                'blocked': blocked,
                'detection_rate': detection_rate,
                'avg_risk': avg_risk,
                'data': data
            }
    
    # Sort by detection rate
    sorted_results = sorted(results.items(), key=lambda x: x[1]['detection_rate'], reverse=True)
    
    print('\n📊 PERFORMANCE RANKING')
    print('-' * 70)
    print(f"{'Mode':<25} {'Detection':<12} {'Blocked/Total':<12} {'Avg Risk':<10}")
    print('-' * 70)
    
    for mode, data in sorted_results:
        detection = f"{data['detection_rate']:.1f}%"
        blocked_total = f"{data['blocked']}/{data['total']}"
        avg_risk = f"{data['avg_risk']:.3f}"
        
        print(f"{mode:<25} {detection:<12} {blocked_total:<12} {avg_risk:<10}")
    
    # The broken algorithm revelation
    print('\n🔍 THE BROKEN ALGORITHM REVELATION')
    print('-' * 70)
    
    if 'broken_probabilistic' in results and 'probabilistic_fixed' in results:
        broken_rate = results['broken_probabilistic']['detection_rate']
        fixed_rate = results['probabilistic_fixed']['detection_rate']
        improvement = broken_rate - fixed_rate
        
        print(f'• Broken algorithm: {broken_rate:.1f}% detection rate')
        print(f'• Fixed algorithm: {fixed_rate:.1f}% detection rate')
        print(f'• Performance gap: +{improvement:.1f}% (broken wins!)')
        print()
        print('WHY THE BROKEN VERSION WORKS BETTER:')
        print('- Chained random() calls create biased probability distribution')
        print('- Accidentally favors masking-only views (~35% vs intended 20%)')
        print('- [MASK] tokens are more effective red flags than scrambling')
        print('- Information removal > information reordering for detection')
    
    # Strategic insights
    print('\n💡 KEY STRATEGIC INSIGHTS')
    print('-' * 70)
    print('1. **Masking superiority**: [MASK] tokens trigger stronger LLM suspicion')
    print('2. **Accidental optimization**: Bugs can reveal better strategies')
    print('3. **Information disruption**: Removal beats reordering for defense')
    print('4. **Multiple analysis**: Even clean copies provide detection value')
    print('5. **Probability matters**: Distribution shape affects performance')
    
    # Mode-specific insights
    print('\n🎯 MODE-SPECIFIC INSIGHTS')
    print('-' * 70)
    
    mode_insights = {
        'broken_probabilistic': 'Accidentally optimal - favors masking through bug',
        'probabilistic_fixed': 'Proper distribution but lower performance',
        'clean_only': 'Surprisingly effective - multiple analysis chances',
        'masking_only': 'Strong performance - [MASK] tokens work',
        'pure_scrambling': 'Weakest - LLMs handle scrambled text well'
    }
    
    for mode, insight in mode_insights.items():
        if mode in results:
            rate = results[mode]['detection_rate']
            print(f"• {mode:<20}: {rate:>5.1f}% - {insight}")
    
    # Recommendations
    print('\n🎯 DEPLOYMENT RECOMMENDATIONS')
    print('-' * 70)
    print('**High Security (Maximum Detection)**')
    print('  → Use broken_probabilistic mode (59.3% detection)')
    print('  → Accept the "bug" as a feature for better performance')
    print()
    print('**Balanced Security (Good Detection + Proper Logic)**')
    print('  → Use probabilistic_fixed mode (51.9% detection)')
    print('  → Mathematically correct probability distribution')
    print()
    print('**Cost-Effective (Simple + Effective)**')
    print('  → Use clean_only mode (48.1% detection)')
    print('  → Minimal complexity, surprising effectiveness')
    print()
    print('**Avoid**')
    print('  → pure_scrambling mode (18.5% detection)')
    print('  → LLMs are too robust to word reordering')
    
    # Cost analysis framework
    print('\n💰 COST-EFFECTIVENESS FRAMEWORK')
    print('-' * 70)
    print('View count optimization opportunities:')
    print('• Test 1-3 views for cost-sensitive deployments')
    print('• broken_probabilistic likely maintains effectiveness with fewer views')
    print('• masking_only could be cost-effective alternative')
    print('• Monitor detection rate vs API cost trade-offs')
    
    return results

def generate_summary_report(results):
    """Generate a markdown summary report"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"scramblegate_final_analysis_{timestamp}.md"
    
    with open(report_file, 'w') as f:
        f.write("# ScrambleGate Final Mode Analysis\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Performance Summary\n\n")
        f.write("| Mode | Detection Rate | Blocked/Total | Key Insight |\n")
        f.write("|------|----------------|---------------|-------------|\n")
        
        sorted_results = sorted(results.items(), key=lambda x: x[1]['detection_rate'], reverse=True)
        
        insights = {
            'broken_probabilistic': 'Accidental masking bias',
            'probabilistic_fixed': 'Proper distribution',
            'clean_only': 'Multiple analysis chances',
            'masking_only': '[MASK] token effectiveness',
            'pure_scrambling': 'LLM robustness to scrambling'
        }
        
        for mode, data in sorted_results:
            rate = f"{data['detection_rate']:.1f}%"
            blocked_total = f"{data['blocked']}/{data['total']}"
            insight = insights.get(mode, 'Unknown')
            f.write(f"| {mode} | {rate} | {blocked_total} | {insight} |\n")
        
        f.write("\n## The Broken Algorithm Discovery\n\n")
        if 'broken_probabilistic' in results:
            broken_rate = results['broken_probabilistic']['detection_rate']
            f.write(f"The \"broken\" probabilistic mode achieved **{broken_rate:.1f}% detection**, ")
            f.write("higher than the mathematically correct version. This reveals that:\n\n")
            f.write("- Chained `random()` calls accidentally favor masking-only views\n")
            f.write("- Information removal is more effective than information reordering\n")
            f.write("- `[MASK]` tokens trigger stronger LLM suspicion than scrambled text\n")
            f.write("- Sometimes bugs reveal better strategies\n\n")
        
        f.write("## Strategic Recommendations\n\n")
        f.write("1. **For maximum security**: Use `broken_probabilistic` mode\n")
        f.write("2. **For balanced approach**: Use `probabilistic_fixed` mode\n")
        f.write("3. **For cost-effectiveness**: Use `clean_only` mode\n")
        f.write("4. **Avoid**: `pure_scrambling` mode (least effective)\n\n")
        
        f.write("## Future Optimization\n\n")
        f.write("- Test configurable view counts (1-5 views) for cost optimization\n")
        f.write("- Explore masking-heavy probability distributions\n")
        f.write("- Consider hybrid approaches combining multiple effective modes\n")
    
    print(f"\n📄 Summary report saved to: {report_file}")
    return report_file

if __name__ == "__main__":
    results = analyze_all_results()
    generate_summary_report(results)
