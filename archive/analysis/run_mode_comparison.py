#!/usr/bin/env python3
"""
Run comparative tests across all 5 scrambling modes.
This script runs each mode sequentially and compares results.
"""

import subprocess
import time
import os
from datetime import datetime

def run_mode_test(mode_name):
    """Run a single mode test and return the output directory"""
    print(f"\n🎲 Starting test for mode: {mode_name}")
    print("=" * 60)
    
    start_time = time.time()
    
    # Run the test
    result = subprocess.run(
        ["python3", "scramblegate_runner.py", mode_name],
        capture_output=True,
        text=True,
        cwd="/home/edward/Projects/ScrambleGate"
    )
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"✅ Mode {mode_name} completed in {duration:.1f}s")
    
    if result.returncode != 0:
        print(f"❌ Error in {mode_name}: {result.stderr}")
        return None
    
    # Extract output directory from stdout
    lines = result.stdout.split('\n')
    output_dir = None
    for line in lines:
        if "Created output directory:" in line:
            output_dir = line.split(": ")[-1]
            break
    
    return output_dir

def compare_results(output_dirs):
    """Compare results across different modes"""
    print("\n📊 COMPARISON SUMMARY")
    print("=" * 60)
    
    for mode, output_dir in output_dirs.items():
        if output_dir and os.path.exists(output_dir):
            report_file = os.path.join(output_dir, "report.md")
            if os.path.exists(report_file):
                # Extract key metrics from report
                with open(report_file, 'r') as f:
                    content = f.read()
                    
                # Look for detection rates
                lines = content.split('\n')
                baseline_rate = "N/A"
                scramblegate_rate = "N/A"
                
                for line in lines:
                    if "Baseline Detection Rate:" in line:
                        baseline_rate = line.split(": ")[-1]
                    elif "ScrambleGate Detection Rate:" in line:
                        scramblegate_rate = line.split(": ")[-1]
                
                print(f"{mode:20s}: Baseline {baseline_rate:>8s} | ScrambleGate {scramblegate_rate:>8s}")
            else:
                print(f"{mode:20s}: Report not found")
        else:
            print(f"{mode:20s}: Test failed")

def main():
    """Run all mode comparisons"""
    modes = [
        "probabilistic",
        "deterministic_masking", 
        "pure_scrambling",
        "masking_only",
        "clean_only"
    ]
    
    print("🔍 SCRAMBLEGATE MODE COMPARISON")
    print("Testing all 5 modes against Agent Dojo injection tasks")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    output_dirs = {}
    
    for mode in modes:
        output_dir = run_mode_test(mode)
        output_dirs[mode] = output_dir
        
        # Brief pause between tests
        time.sleep(2)
    
    # Compare results
    compare_results(output_dirs)
    
    print(f"\n🎯 All mode tests completed!")
    print("Check individual output directories for detailed results.")

if __name__ == "__main__":
    main()
