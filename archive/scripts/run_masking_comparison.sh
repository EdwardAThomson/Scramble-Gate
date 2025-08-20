#!/bin/bash
# Masking token comparison script

echo "🎭 MASKING TOKEN COMPARISON EXPERIMENT"
echo "======================================"

modes=("masking_only" "masking_brackets" "masking_redacted" "masking_asterisks")
descriptions=("[MASK] tokens" "[] tokens" "[REDACTED] tokens" "*** tokens")

for i in "${!modes[@]}"; do
    mode="${modes[$i]}"
    desc="${descriptions[$i]}"
    
    echo ""
    echo "🧪 Testing $mode: $desc"
    echo "-----------------------------------"
    
    python3 scramblegate_runner.py "$mode"
    
    if [ $? -eq 0 ]; then
        echo "✅ $mode completed successfully"
    else
        echo "❌ $mode failed"
    fi
    
    echo "Waiting 5 seconds before next test..."
    sleep 5
done

echo ""
echo "🏁 All masking token tests completed!"
echo "Check the results directories for performance comparison."
