# ScrambleGate

**ScrambleGate** is an experimental technique for defending against **prompt injection attacks** in LLM applications.

It acts as a **stochastic pre-execution gate**: before a prompt is sent to the main model, ScrambleGate randomly samples and scrambles parts of the input, then runs them through heuristic and ML-based detectors.  

If malicious intent is detected in any scrambled view, execution is blocked.

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

```bash
git clone https://github.com/EdwardAThomson/Scramble-Gate.git
cd ScrambleGate

# Install dependencies
pip install -r requirements.txt

# Set up environment
echo "OPENAI_API_KEY=your-key-here" > .env

# Run comprehensive Agent Dojo benchmark
python scramblegate_runner.py

# Or test individual prompts
python scramblegate.py
