#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEM5_ROOT="${GEM5_ROOT:-/home/tjossen/src/gem5}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
BIN="$SCRIPT_DIR/pandora_imp_poc"
ASM="$SCRIPT_DIR/pandora_imp_poc.s"
ASM_SNIP="$OUT_DIR/attacker_kernel_only.s"
OBJDIS="$OUT_DIR/attacker_kernel_only.objdump"
LOG="$OUT_DIR/impv2_pandora_debug.log"
N_ITERS="${N_ITERS:-4096}"
DEBUG_FLAGS="${DEBUG_FLAGS:-HWPrefetch,LightPrefetch}"

# Defaults chosen to avoid interactive build prompts unless explicitly needed.
BUILD_GEM5="${BUILD_GEM5:-0}"
RUN_GEM5="${RUN_GEM5:-1}"

mkdir -p "$OUT_DIR"

echo "[1/4] Building PoC binary + assembly"
make -C "$SCRIPT_DIR" clean all

echo "[2/4] Verifying dependent load chain in assembly"
awk '/attacker_kernel/{flag=1} /\\.size\\s+attacker_kernel/{if(flag){print; flag=0}} flag{print}' "$ASM" > "$ASM_SNIP"
objdump -d "$BIN" | sed -n '/<attacker_kernel>/,/<main>/p' > "$OBJDIS"

grep -n "mov.*\\[.*\\]" "$ASM_SNIP" | head -n 40 || true

if ! grep -Eq "mov[[:space:]]+\(%rsi\),%eax" "$OBJDIS"; then
    echo "WARNING: expected load of Z[i] in attacker_kernel not found in objdump"
fi

if ! grep -Eq "mov[[:space:]]+\(%rax\),%rax|mov[[:space:]]+\(%rax\),%eax" "$OBJDIS"; then
    echo "WARNING: expected dependent load in attacker_kernel not found in objdump"
fi

if [[ "$BUILD_GEM5" == "1" ]]; then
    echo "[3/4] Building gem5 (X86 opt)"
    scons -C "$GEM5_ROOT" build/X86/gem5.opt -j "${JOBS:-16}"
else
    echo "[3/4] Skipping gem5 rebuild (set BUILD_GEM5=1 to force build)"
fi

if [[ "$RUN_GEM5" == "1" ]]; then
    echo "[4/4] Running gem5 with debug flags: $DEBUG_FLAGS"
    rm -f "$LOG"
    set +e
    "$GEM5_ROOT/build/X86/gem5.opt" \
        --debug-flags="$DEBUG_FLAGS" \
        --debug-file="$LOG" \
        "$GEM5_ROOT/configs/deprecated/example/se.py" \
        --cpu-type=X86O3CPU \
        --caches \
        --l2cache \
        --l1d-hwp-type=IMPv2Prefetcher \
        --l2-hwp-type=IMPv2Prefetcher \
        --cmd="$BIN" \
        --options="$N_ITERS"
    GEM5_RC=$?
    set -e
    if [[ "$GEM5_RC" -ne 0 ]]; then
        echo "WARNING: gem5 exited with code $GEM5_RC (continuing to parse debug log)."
    fi
else
    echo "[4/4] Skipping gem5 run (set RUN_GEM5=1 to run)"
fi

if [[ "$RUN_GEM5" == "1" ]]; then
    if [[ ! -f "$LOG" ]]; then
        echo "ERROR: debug log was not generated: $LOG"
        exit 1
    fi

    kernel_start_hex=$(nm -n "$BIN" | awk '$3=="attacker_kernel" {print $1}')
    kernel_end_hex=$(nm -n "$BIN" |
        awk '
            $3=="attacker_kernel" {found=1; next}
            found && $2 ~ /^[tTwW]$/ {print $1; exit}
        ')

    if [[ -z "$kernel_start_hex" ]]; then
        echo "ERROR: failed to resolve attacker_kernel symbol in $BIN"
        exit 1
    fi

    if [[ -z "$kernel_end_hex" ]]; then
        kernel_end_hex=$(printf "%x" $((16#$kernel_start_hex + 0x200)))
    fi

    kernel_start=$((16#$kernel_start_hex))
    kernel_end=$((16#$kernel_end_hex))

    KERNEL_LOG="$OUT_DIR/impv2_pandora_debug_attacker_kernel.log"
    LO_HEX="$kernel_start_hex" HI_HEX="$kernel_end_hex" perl -ne '
        BEGIN {
            $lo = hex($ENV{LO_HEX});
            $hi = hex($ENV{HI_HEX});
        }
        if (/pc=0x([0-9a-fA-F]+)/) {
            $pc = hex($1);
            if ($pc >= $lo && $pc < $hi) {
                print;
            }
        }
    ' "$LOG" > "$KERNEL_LOG"

    if [[ ! -s "$KERNEL_LOG" ]]; then
        echo "WARNING: attacker-kernel filtered log is empty."
        echo "         In gem5 SE mode, guest PCs may be relocated relative to nm symbol addresses."
        echo "         Falling back to full log counts for functional checks."
        KERNEL_LOG="$LOG"
    fi

    stream_detected_kernel=$(grep -c "IMPv2 stream detected" "$KERNEL_LOG" || true)
    deferred_ctx_kernel=$(grep -c "IMPv2 deferred ctx" "$KERNEL_LOG" || true)
    index_access_req_kernel=$(grep -c "IMPv2 index access:" "$KERNEL_LOG" || true)
    index_access_learn_kernel=$(grep -c "IMPv2 learn index access:" "$KERNEL_LOG" || true)
    ipd_match_kernel=$(grep -c "IMPv2 IPD match" "$KERNEL_LOG" || true)
    notify_index_pf_kernel=$(grep -c "IMPv2 notifyFill index->pf" "$KERNEL_LOG" || true)
    deferred_indirect_pf_kernel=$(grep -c "IMPv2 deferred indirect pf" "$KERNEL_LOG" || true)
    skip_candidate_kernel=$(grep -c "IMPv2 skip indirect candidate" "$KERNEL_LOG" || true)
    missing_index_data_kernel=$(grep -c "IMPv2 index access missing data" "$KERNEL_LOG" || true)

    stream_detected=$(grep -c "IMPv2 stream detected" "$LOG" || true)
    deferred_ctx=$(grep -c "IMPv2 deferred ctx" "$LOG" || true)
    index_access_req=$(grep -c "IMPv2 index access:" "$LOG" || true)
    index_access_learn=$(grep -c "IMPv2 learn index access:" "$LOG" || true)
    ipd_match=$(grep -c "IMPv2 IPD match" "$LOG" || true)
    notify_index_pf=$(grep -c "IMPv2 notifyFill index->pf" "$LOG" || true)
    deferred_indirect_pf=$(grep -c "IMPv2 deferred indirect pf" "$LOG" || true)
    skip_candidate=$(grep -c "IMPv2 skip indirect candidate" "$LOG" || true)
    missing_index_data=$(grep -c "IMPv2 index access missing data" "$LOG" || true)
    missing_fill_data=$(grep -c "IMPv2 notifyFill missing data" "$LOG" || true)

    echo
    echo "=== IMPv2 Debug Summary ==="
    echo "Log: $LOG"
    echo "stream detected           : $stream_detected"
    echo "deferred ctx stored       : $deferred_ctx"
    echo "index access observed(req): $index_access_req"
    echo "index access learned(fill): $index_access_learn"
    echo "IPD match learned         : $ipd_match"
    echo "notifyFill index->pf      : $notify_index_pf"
    echo "deferred indirect pf      : $deferred_indirect_pf"
    echo "skip indirect candidate   : $skip_candidate"
    echo "index access missing data : $missing_index_data"
    echo "notifyFill missing data   : $missing_fill_data"

    echo
    echo "=== IMPv2 Attacker-Kernel-Only Summary ==="
    echo "Symbol range: [0x$kernel_start_hex, 0x$kernel_end_hex)"
    echo "Filtered log: $KERNEL_LOG"
    echo "stream detected           : $stream_detected_kernel"
    echo "deferred ctx stored       : $deferred_ctx_kernel"
    echo "index access observed(req): $index_access_req_kernel"
    echo "index access learned(fill): $index_access_learn_kernel"
    echo "IPD match learned         : $ipd_match_kernel"
    echo "notifyFill index->pf      : $notify_index_pf_kernel"
    echo "deferred indirect pf      : $deferred_indirect_pf_kernel"
    echo "skip indirect candidate   : $skip_candidate_kernel"
    echo "index access missing data : $missing_index_data_kernel"

    echo
    if (( stream_detected > 0 )); then
        echo "PASS: IMPv2 is active (stream events observed)."
    else
        echo "FAIL: no IMPv2 stream activity observed in this run."
        exit 1
    fi

    if (( (index_access_req_kernel + index_access_learn_kernel) > 0 && ipd_match_kernel > 0 )); then
        echo "PASS: index extraction and IPD matching are active in selected log scope."
    else
        echo "INFO: full 2-layer learning (index + IPD match) not observed in selected log scope."
        echo "      Note: request-path index extraction can be missing when PrefetchInfo hasData is false."
        echo "      Fill-path learning is reported via 'IMPv2 learn index access'."
    fi

    if (( notify_index_pf_kernel > 0 || deferred_indirect_pf_kernel > 0 )); then
        echo "INFO: Deferred/indirect issue stage is active for attacker_kernel."
    else
        echo "INFO: Deferred/indirect issue stage is still gated for attacker_kernel."
    fi
fi

echo "Done. Debug log: $LOG"
echo "Key markers to inspect:"
echo "  IMPv2 stream detected"
echo "  IMPv2 deferred ctx"
echo "  IMPv2 index access"
echo "  IMPv2 learn index access"
echo "  IMPv2 IPD match"
echo "  IMPv2 notifyFill index->pf"
echo "  IMPv2 deferred indirect pf"
