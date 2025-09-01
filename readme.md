# ScrambleGate

**ScrambleGate** is an experimental technique for defending against **prompt injection attacks** in LLM applications.

⚠️ **Experimental: do not use in production. This technique doesn't work.** ⚠️

## Overview
The intention was a tool that acts as a **stochastic pre-execution gate**: before a prompt is sent to the main model, ScrambleGate randomly samples and scrambles parts of the input, then sends them to an LLM for safety classification.

If malicious intent is detected in any scrambled view, execution is blocked. However, performance is made worse whenever inputs are scrambled.

An additional idea that's tried here is the (stochastic) masking of inputs, which performed better than scrambling, but it introduced false positives (the LLM became more suspicious).

---

## 🎯 Motivation

Prompt injection is a growing attack vector for LLM-based systems.  
Most defenses rely on static filters or rule-based scans, which attackers can adapt to.

ScrambleGate introduces **randomization** into the detection pipeline, inspired by **ASLR (Address Space Layout Randomization)** in computer security:

- Just as ASLR randomizes memory layouts to make exploits unreliable,  
- ScrambleGate randomizes prompt views (scrambles + samples), so attackers cannot predict what the gate will check.

---

## 🔑 Core Ideas

1. **Normalize & Deobfuscate**  
   - Unicode cleanup, zero-width stripping, homoglyph normalization.  
   - Base64/hex/URL decoding for obfuscated payloads.  

2. **Windowed Sampling with Coverage**  
   - Split input into overlapping windows.  
   - Track coverage (n-gram shingles) to ensure broad inspection.  

3. **Randomized Scrambles**  
   - Generate multiple “views” of each window by masking tokens, lightly shuffling sentences, or leaving clean.  
   - Run detectors across all views.  

4. **Multi-Detector Scoring**  
   - Regex/rule heuristics (e.g., “ignore previous instructions”, “reveal system prompt”).  
   - Structural anomaly checks (encoded blobs, suspicious repetition).  
   - (Pluggable) ML classifier or LLM probe for semantic intent.  

5. **Stochastic Blocking**  
   - Any high-risk score blocks the prompt.  
   - Coverage below threshold → escalate for review.  

---

## 📁 Project Structure

### Core Scripts

- **`scramblegate.py`** - Main ScrambleGate defense implementation
  - Core `gate_prompt()` function with windowing, scrambling, and detection
  - Baseline LLM detection for comparison (`baseline_llm_check()`)
  - Configurable policies and detection thresholds

- **`scramblegate_runner.py`** - Agent Dojo integration and benchmarking
  - Tests ScrambleGate against real prompt injection attacks
  - Integrates with Agent Dojo test suites (banking, slack, travel, workspace)
  - Generates comprehensive markdown reports with baseline comparisons
  - Saves detailed audit trails including scrambled views

- **`test_scramblegate.py`** - Unit tests for core functionality
  - Tests gate logic, scrambling functions, and detection mechanisms

### Dependencies

- **`requirements.txt`** - Python package dependencies
- **`.env`** - Environment variables (create with your `OPENAI_API_KEY`)

## ⚙️ Quick Start

1. Set up your environment:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

2. Run a test with different scrambling modes:
```bash
# Test with probabilistic scrambling (recommended)
python scramblegate_runner.py probabilistic

# Test with masking only
python scramblegate_runner.py masking_only

# Test with pure scrambling
python scramblegate_runner.py pure_scrambling

# Test with clean copies only
python scramblegate_runner.py clean_only

# Test with deterministic masking + scrambling
python scramblegate_runner.py deterministic_masking
```

This will test ScrambleGate against Agent Dojo prompt injection benchmarks and generate a detailed report.

## 🎯 Scrambling Mode Performance

Based on Agent Dojo benchmark testing (27 injection tasks):

| Mode | Detection Rate | Key Insight |
|------|----------------|-------------|
| **broken_probabilistic** | **59.3%** | **Accidental masking bias (highest performance)** |
| probabilistic | 51.9% | Balanced mix of clean, masked, scrambled views |
| clean_only | 48.1% | Multiple analysis chances with identical copies |
| masking_only | 33.3% | [MASK] tokens trigger LLM suspicion |
| deterministic_masking | 25.9% | Fixed patterns easier to bypass |
| pure_scrambling | 18.5% | LLMs handle scrambled text well |

## 🔍 The Broken Algorithm Discovery

We discovered that the original "buggy" probabilistic implementation achieved **59.3% detection** - significantly higher than the mathematically correct version (51.9%). 

**Why the broken version works better:**
- Chained `random()` calls accidentally favor masking-only views (~35% vs intended 20%)
- `[MASK]` tokens are more effective red flags than scrambled text
- Information removal beats information reordering for prompt injection detection
- Sometimes bugs reveal better strategies than intended designs

## 🎯 Deployment Recommendations

### Detection vs Precision Trade-offs

| Priority | Mode | Detection Rate | False Positive Rate | Best For |
|----------|------|----------------|-------------------|----------|
| **High Precision** | `masking_brackets` | 29.6% | 0.0% | Production systems requiring minimal false positives |
| **Balanced** | `clean_only` | 48.1% | 7.4% | General use (best F1 score: 0.880) |
| **Maximum Detection** | `broken_probabilistic` | 59.3% | ~7-8% | High-security environments accepting false positives |

### Strategic Guidance
- **Production Systems**: Use `balanced_precision` mode (combines clean views + subtle masking)
- **Security-Critical**: Use `broken_probabilistic` mode (highest detection, accept false positives)
- **Cost-Conscious**: Use `clean_only` mode (surprising effectiveness, minimal complexity)
- **Avoid**: `pure_scrambling` mode (18.5% detection, LLMs handle scrambled text well)

### Masking Token Impact
- **`[MASK]`**: Medium detection, medium false positives (ML training association)
- **`[]`**: Lower detection, zero false positives (subtle placeholder)
- **`[REDACTED]`**: High detection, high false positives (security signal triggers suspicion)

**Key Insights:**
- **Masking beats scrambling**: `[MASK]` tokens trigger LLM suspicion more than word reordering
- **Probabilistic unpredictability**: Random patterns prevent attack adaptation
- **Clean copies work**: Multiple identical views give LLMs more analysis opportunities
