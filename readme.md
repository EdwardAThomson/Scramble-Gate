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

## ⚙️ Usage

```bash
git clone https://github.com/YOURNAME/scramblegate.git
cd scramblegate
python gate.py
