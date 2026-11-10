#!/bin/bash
# Compare the pre-review and binding rounds; an optional section name limits the output.
S=$(dirname "$(readlink -f "$0")")
out=$(python3 "$S/compare-rounds.py" "$HOME/tn-cuda/results/final" "$HOME/tn-cuda/results/${ROUND:-binding-r2}" 2>&1)
if [ -n "${1:-}" ]; then
    printf '%s\n' "$out" | awk -v want="## $1" '/^## /{show = ($0 == want)} show' | cut -c1-400
else
    printf '%s\n' "$out" | cut -c1-400
fi
