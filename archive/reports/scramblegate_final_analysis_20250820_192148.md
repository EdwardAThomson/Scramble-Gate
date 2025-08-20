# ScrambleGate Final Mode Analysis

Generated: 2025-08-20 19:21:48

## Performance Summary

| Mode | Detection Rate | Blocked/Total | Key Insight |
|------|----------------|---------------|-------------|
| broken_probabilistic | 59.3% | 16/27 | Accidental masking bias |
| probabilistic_fixed | 51.9% | 14/27 | Proper distribution |
| clean_only | 48.1% | 13/27 | Multiple analysis chances |
| masking_only | 33.3% | 9/27 | [MASK] token effectiveness |
| pure_scrambling | 18.5% | 5/27 | LLM robustness to scrambling |

## The Broken Algorithm Discovery

The "broken" probabilistic mode achieved **59.3% detection**, higher than the mathematically correct version. This reveals that:

- Chained `random()` calls accidentally favor masking-only views
- Information removal is more effective than information reordering
- `[MASK]` tokens trigger stronger LLM suspicion than scrambled text
- Sometimes bugs reveal better strategies

## Strategic Recommendations

1. **For maximum security**: Use `broken_probabilistic` mode
2. **For balanced approach**: Use `probabilistic_fixed` mode
3. **For cost-effectiveness**: Use `clean_only` mode
4. **Avoid**: `pure_scrambling` mode (least effective)

## Future Optimization

- Test configurable view counts (1-5 views) for cost optimization
- Explore masking-heavy probability distributions
- Consider hybrid approaches combining multiple effective modes
