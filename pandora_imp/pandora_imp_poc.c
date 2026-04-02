#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef N
#define N 64
#endif

struct x_object {
    uint8_t prefix[0xd0];
    uint8_t array[N];
};

/*
 * Pandora-style 3-level dependent memory access shape:
 *   X[Y[Z[i]]]
 * We keep explicit bounds checks to emulate the paper's "if (!v)" guard style.
 */
static __attribute__((noinline)) int attacker_kernel(
    const uint32_t *Z,
    const uint64_t *Y,
    const struct x_object *X_obj,
    size_t z_len,
    size_t y_len,
    size_t x_len,
    size_t n)
{
    volatile int sink = 0;

    for (size_t j = 0; j < n; j++) {
        size_t i = j;
        if (i >= z_len) {
            return sink;
        }

        uint32_t xval = 0;
        int ok = 0;

#if defined(__x86_64__)
    (void)y_len;
        /*
         * Inline-asm dependent access shape (AT&T syntax), matching the
         * paper's 3-level chain as closely as practical in C:
         *   mov 0(%rsi), %eax      ; z = Z[i]
         *   cmp $0x40, %rax
         *   jae fail
         *   shl $0x3, %rax         ; 64-bit Y entries
         *   add %rdi, %rax         ; rax = &Y[Z[i]]
         *   mov 0(%rax), %rax      ; y = Y[Z[i]]
         *   mov X_obj, %rdi
         *   add $0xd0, %rdi        ; rdi = &X array
         *   mov %rax, %rsi
         *   add %rdi, %rsi         ; rsi = &X[y]
         *   mov 0(%rsi), %eax      ; x = X[Y[Z[i]]]
         */
        __asm__ __volatile__(
            "mov %[zptr], %%rsi\n\t"
            "mov %[ybase], %%rdi\n\t"
            "mov 0x0(%%rsi), %%eax\n\t"
            "cmp $0x40, %%rax\n\t"
            "jae 1f\n\t"
            "shl $0x3, %%rax\n\t"
            "add %%rdi, %%rax\n\t"
            "mov 0x0(%%rax), %%rax\n\t"
            "cmp %[x_len], %%rax\n\t"
            "jae 1f\n\t"
            "mov %[x_obj], %%rdi\n\t"
            "add $0xd0, %%rdi\n\t"
            "mov %%rax, %%rsi\n\t"
            "add %%rdi, %%rsi\n\t"
            "mov 0x0(%%rsi), %%eax\n\t"
            "mov $1, %[ok_out]\n\t"
            "1:\n\t"
            : "=a"(xval), [ok_out] "+r"(ok)
            : [zptr] "r"(&Z[i]), [ybase] "r"(Y), [x_obj] "r"(X_obj), [x_len] "r"(x_len)
            : "rsi", "rdi", "cc", "memory");
#else
        uint32_t z = Z[i];
        ok = (z < y_len);
        if (ok) {
            uint64_t y = Y[z];
            if (y < x_len) {
                xval = X_obj->array[y];
                ok = 1;
            }
        }
#endif

        if (!ok) {
            return sink;
        }

        sink ^= (uint8_t)xval;
    }

    return sink;
}

int main(int argc, char **argv)
{
    size_t n = (argc > 1) ? strtoull(argv[1], NULL, 10) : N;
    if (n == 0 || n > N) {
        n = N;
    }
    uint32_t *Z = (uint32_t *)malloc(sizeof(uint32_t) * N);
    uint64_t *Y = (uint64_t *)malloc(sizeof(uint64_t) * N);
    struct x_object *X_obj = (struct x_object *)calloc(1, sizeof(struct x_object));
    if (!Z || !Y || !X_obj) {
        return 1;
    }

    for (size_t i = 0; i < N; i++) {
        Z[i] = (uint32_t)i;
        Y[i] = (uint64_t)i;
        X_obj->array[i] = (uint8_t)(i & 0xff);
    }

    /* Out-of-bounds style target, analogous to the Pandora narrative. */
    Z[N - 1] = (uint32_t)(N + 8);

    int out = attacker_kernel(Z, Y, X_obj, n, n, n, n);
    printf("result=%d\n", out);

    free(Z);
    free(Y);
    free(X_obj);
    return 0;
}
