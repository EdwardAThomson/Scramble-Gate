#!/usr/bin/env python3
"""
Script to inspect the exact raw prompts from saved output files.
Shows the original prompts exactly as they were received from Agent Dojo.
"""

import os
import json
import glob

def inspect_saved_prompts():
    """Inspect raw prompts from the latest output directory"""
    
    # Find the latest results directory
    result_dirs = glob.glob("scramblegate_results_*")
    if not result_dirs:
        print("❌ No results directories found")
        return
    
    latest_dir = max(result_dirs)
    print(f"📁 Inspecting: {latest_dir}")
    
    # Check the raw JSON results
    json_file = os.path.join(latest_dir, "results.json")
    if os.path.exists(json_file):
        print(f"\n📋 **RAW JSON DATA**:")
        print("=" * 60)
        
        with open(json_file, 'r') as f:
            results = json.load(f)
        
        print(f"Total results: {len(results)}")
        
        # Show first few raw prompts
        for i, result in enumerate(results[:3]):
            print(f"\n🔍 **Result {i+1}**:")
            print(f"Verdict: {result.get('verdict', 'unknown')}")
            print(f"Risk: {result.get('risk', 'unknown')}")
            print(f"Suite: {result.get('suite', 'unknown')}")
            print(f"Attack Type: {result.get('attack_type', 'unknown')}")
            print(f"Raw prompt length: {len(result.get('prompt', ''))}")
            print(f"Raw prompt:")
            print(f"'{result.get('prompt', 'NO PROMPT FOUND')}'")
            print("-" * 40)
    
    # Check individual prompt files
    prompts_dir = os.path.join(latest_dir, "prompts")
    if os.path.exists(prompts_dir):
        print(f"\n📄 **INDIVIDUAL PROMPT FILES**:")
        print("=" * 60)
        
        prompt_files = sorted(glob.glob(os.path.join(prompts_dir, "*.txt")))
        print(f"Found {len(prompt_files)} prompt files")
        
        # Show first few files
        for i, file_path in enumerate(prompt_files[:3]):
            filename = os.path.basename(file_path)
            print(f"\n📝 **{filename}**:")
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Extract just the original prompt section
            lines = content.split('\n')
            in_original = False
            original_prompt = []
            
            for line in lines:
                if line.strip() == "ORIGINAL PROMPT:":
                    in_original = True
                    continue
                elif line.strip().startswith("--"):
                    if in_original:
                        break
                elif in_original:
                    original_prompt.append(line)
            
            raw_prompt = '\n'.join(original_prompt).strip()
            print(f"Raw prompt ({len(raw_prompt)} chars):")
            print(f"'{raw_prompt}'")
            print("-" * 40)

def inspect_agent_dojo_source():
    """Show what Agent Dojo actually provides as input"""
    
    print(f"\n🤖 **AGENT DOJO SOURCE INSPECTION**:")
    print("=" * 60)
    
    try:
        from agentdojo.agent_pipeline.pipeline import AgentPipeline
        from agentdojo.task_suite.task_suite import TaskSuite
        
        # Load a test suite to see raw data
        suite = TaskSuite.from_huggingface("palisade/agentdojo", "banking")
        
        print(f"Suite: banking")
        print(f"Total tasks: {len(suite.tasks)}")
        
        # Show first few tasks exactly as they come from Agent Dojo
        for i, task in enumerate(suite.tasks[:3]):
            print(f"\n📋 **Task {i+1}**:")
            print(f"ID: {task.ID}")
            print(f"Type: {getattr(task, 'ATTACK_TYPE', 'unknown')}")
            print(f"Goal: '{task.goal}'")
            print(f"Goal length: {len(task.goal)}")
            print(f"Goal repr: {repr(task.goal)}")
            print("-" * 40)
            
    except Exception as e:
        print(f"❌ Could not inspect Agent Dojo source: {e}")

if __name__ == "__main__":
    print("🔍 RAW PROMPT INSPECTION")
    print("=" * 80)
    
    inspect_saved_prompts()
    inspect_agent_dojo_source()
    
    print(f"\n✅ **INSPECTION COMPLETE**")
    print("This shows the exact raw prompts as saved and as received from Agent Dojo.")
