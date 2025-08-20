# ScrambleGate Archive

This directory contains experimental scripts, analysis tools, test files, and historical results from the ScrambleGate optimization research.

## Directory Structure

### `/analysis/`
Research and analysis scripts used during mode optimization:
- `ai_helper.py` - Multi-model LLM testing utilities
- `analyze_false_positives.py` - False positive rate analysis
- `analyze_mode_results.py` - Mode performance comparison
- `final_mode_analysis.py` - Comprehensive final analysis
- `inspect_raw_prompts.py` - Raw prompt inspection tools
- `run_mode_comparison.py` - Automated mode testing

### `/tests/`
Experimental and validation test scripts:
- `show_llm_prompt_format.py` - LLM prompt format visualization
- `test_all_modes.py` - Multi-mode testing demonstration
- `test_masking_experiment.py` - Masking token experiments
- `test_masking_tokens.py` - Masking token effectiveness tests
- `test_modes_simple.py` - Simple mode validation
- `test_scramblegate.py` - Core functionality tests
- `test_scrambling.py` - Scrambling algorithm tests
- `test_view_counts.py` - View count optimization tests

### `/scripts/`
Shell scripts for batch operations:
- `run_masking_comparison.sh` - Automated masking token comparison

### `/reports/`
Historical analysis reports:
- `scramblegate_final_analysis_20250820_192148.md` - Earlier analysis report

### `/results/`
Complete test result directories from Agent Dojo benchmarking:
- `scramblegate_results_GPT4o_*` - Various mode test results with full data

## Key Research Findings

The scripts in this archive were used to discover:
1. The "broken" probabilistic algorithm's superior performance (59.3% vs 51.9%)
2. Pure masking effectiveness over combined masking+scrambling
3. Masking token impact on false positive rates
4. Clean-only mode's surprising effectiveness

## Usage

These archived files are preserved for:
- Research reproducibility
- Historical reference
- Advanced experimentation
- Academic analysis

For current usage, refer to the main repository files:
- `scramblegate.py` - Core implementation
- `scramblegate_runner.py` - Agent Dojo integration
- `readme.md` - Usage instructions
- `ScrambleGate_Optimization_Report.md` - Research findings
