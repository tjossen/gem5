CC ?= gcc
CFLAGS ?= -O0 -fno-tree-vectorize -fno-unroll-loops -fno-inline -fno-ipa-cp -fno-ipa-cp-clone
LDFLAGS ?= -static

all: pandora_imp_poc pandora_imp_poc.s

pandora_imp_poc: pandora_imp_poc.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

pandora_imp_poc.s: pandora_imp_poc.c
	$(CC) $(CFLAGS) -S -masm=intel -fverbose-asm -o $@ $<

asm-check: pandora_imp_poc.s
	@echo "Checking for dependent load chain in attacker_kernel..."
	@awk '/attacker_kernel/{flag=1} /\.size\s+attacker_kernel/{if(flag){print; flag=0}} flag{print}' pandora_imp_poc.s > attacker_kernel_only.s
	@grep -n "mov.*\[.*\]" attacker_kernel_only.s || true
	@echo "Look for sequence: load Z[i] -> bounds check -> load Y[z] -> bounds check -> load X[y]"

clean:
	rm -f pandora_imp_poc pandora_imp_poc.s attacker_kernel_only.s

.PHONY: all asm-check clean
