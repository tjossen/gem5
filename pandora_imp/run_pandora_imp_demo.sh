#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEM5_ROOT="${GEM5_ROOT:-/home/tjossen/src/gem5}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out}"
BIN="$SCRIPT_DIR/pandora_imp_poc"
ASM="$SCRIPT_DIR/pandora_imp_poc.s"
ASM_SNIP="$OUT_DIR/attacker_kernel_only.s"
LOG="$OUT_DIR/impv2_pandora_debug.log"
N_ITERS="${N_ITERS:-64}"

# Defaults chosen to avoid interactive build prompts unless explicitly needed.
BUILD_GEM5="${BUILD_GEM5:-0}"
RUN_GEM5="${RUN_GEM5:-1}"

mkdir -p "$OUT_DIR"

echo "[1/4] Building PoC binary + assembly"
make -C "$SCRIPT_DIR" clean all

echo "[2/4] Verifying dependent load chain in assembly"
awk '/attacker_kernel/{flag=1} /\\.size\\s+attacker_kernel/{if(flag){print; flag=0}} flag{print}' "$ASM" > "$ASM_SNIP"

grep -n "mov.*\\[.*\\]" "$ASM_SNIP" || true

APP_SNIP="$OUT_DIR/attacker_kernel_app.s"
awk '/#APP/{flag=1; next} /#NO_APP/{flag=0} flag{print}' "$ASM_SNIP" > "$APP_SNIP"

if ! grep -Eq "mov 0x0\(%rsi\), %eax" "$APP_SNIP"; then
    echo "ERROR: expected Z[i]-style load not found in #APP block"
fi

if ! grep -Eq "mov 0x0\(%rax\), %rax" "$APP_SNIP"; then
    echo "ERROR: expected dependent load from Y[z]-style address not found in #APP block"
fi

if ! grep -Eq "add %rdi, %rsi" "$APP_SNIP" || \
   ! grep -Eq "mov 0x0\(%rsi\), %eax" "$APP_SNIP"; then
    echo "WARNING: expected X[y]-style final load form not found exactly; inspect $APP_SNIP manually"
fi

if [[ "$BUILD_GEM5" == "1" ]]; then
    echo "[3/4] Building gem5 (X86 opt)"
    scons -C "$GEM5_ROOT" build/X86/gem5.opt -j "${JOBS:-16}"
else
    echo "[3/4] Skipping gem5 rebuild (set BUILD_GEM5=1 to force build)"
fi

if [[ "$RUN_GEM5" == "1" ]]; then
    echo "[4/4] Running gem5 with HWPrefetch debug"
    rm -f "$LOG"
    "$GEM5_ROOT/build/X86/gem5.opt" \
        --debug-flags=HWPrefetch \
        --debug-file="$LOG" \
        "$GEM5_ROOT/configs/deprecated/example/se.py" \
        --cpu-type=X86O3CPU \
        --caches \
        --l2cache \
        --l1d-hwp-type=IMPv2Prefetcher \
        --l2-hwp-type=IMPv2Prefetcher \
        --cmd="$BIN" \
        --options="$N_ITERS"
else
    echo "[4/4] Skipping gem5 run (set RUN_GEM5=1 to run)"
fi

if [[ "$RUN_GEM5" == "1" ]]; then
    if [[ ! -f "$LOG" ]]; then
        echo "ERROR: debug log was not generated: $LOG"
        exit 1
    fi

    stream_detected=$(grep -c "IMPv2 stream detected" "$LOG" || true)
    deferred_ctx=$(grep -c "IMPv2 deferred ctx" "$LOG" || true)
    index_access=$(grep -c "IMPv2 index access:" "$LOG" || true)
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
    echo "index access observed     : $index_access"
    echo "IPD match learned         : $ipd_match"
    echo "notifyFill index->pf      : $notify_index_pf"
    echo "deferred indirect pf      : $deferred_indirect_pf"
    echo "skip indirect candidate   : $skip_candidate"
    echo "index access missing data : $missing_index_data"
    echo "notifyFill missing data   : $missing_fill_data"

    echo
    stage1_ok=0
    stage2_ok=0

    # Stage 1: stream detector learns and stores deferred metadata.
    if (( stream_detected > 0 && deferred_ctx > 0 )); then
        stage1_ok=1
        echo "STAGE-1 PASS: stream detector and deferred context path are active."
    else
        echo "STAGE-1 FAIL: expected stream/deferred-context behavior was not observed."
    fi

    # Stage 2: index-dependent indirect learning/issuance pipeline.
    if (( index_access > 0 && (ipd_match > 0 || notify_index_pf > 0 || deferred_indirect_pf > 0) )); then
        stage2_ok=1
        echo "STAGE-2 PASS: index/IPD/indirect-prefetch path is active."
    else
        echo "STAGE-2 NOT VERIFIED: no evidence of complete index->IPD->indirect PF path."
        echo "  Hint: repeated 'hasData=0' or 'index access missing data' often gates this stage."
    fi

    echo
    if (( stage1_ok == 1 && stage2_ok == 1 )); then
        echo "OVERALL: FULL IMPv2 pipeline observed for this workload."
    elif (( stage1_ok == 1 )); then
        echo "OVERALL: PARTIAL validation only (stream path active, indirect path not verified)."
        echo "Do NOT claim full IMP/Pandora-equivalent behavior from this run alone."
    else
        echo "OVERALL: validation failed."
        exit 1
    fi
fi

echo "Done. Debug log: $LOG"
echo "Key markers to inspect:"
echo "  IMPv2 stream detected"
echo "  IMPv2 deferred ctx"
echo "  IMPv2 index access"
echo "  IMPv2 IPD match"
echo "  IMPv2 notifyFill index->pf"
echo "  IMPv2 deferred indirect pf"
