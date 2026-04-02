Pandora IMP PoC (non-exploit)

This folder contains a minimal test program to recreate the dependent memory
access structure discussed in the Pandora paper:

    X[Y[Z[i]]]

Files:
- pandora_imp_poc.c : small C program with explicit bounds checks.
- Makefile          : build binary and Intel-syntax assembly.

Usage:
1) make
2) make asm-check
3) ./pandora_imp_poc

Full end-to-end demo (build + asm check + gem5 run + debug log):
1) chmod +x run_pandora_imp_demo.sh
2) ./run_pandora_imp_demo.sh

Expected assembly shape in attacker_kernel:
- load index stream element (Z[i])
- bounds compare
- dependent load (Y[Z[i]])
- bounds compare
- dependent load (X[Y[Z[i]]])

Expected IMPv2 debug markers in out/impv2_pandora_debug.log:
- IMPv2 stream detected
- IMPv2 deferred ctx
- IMPv2 index access
- IMPv2 IPD match
- IMPv2 notifyFill index->pf
- IMPv2 deferred indirect pf

Notes:
- This is not a leak exploit. It is only a structural trigger candidate for
  data memory-dependent prefetching behavior.
- The final iteration intentionally places an out-of-range value in Z[N-1]
  so the software guard path is exercised.
