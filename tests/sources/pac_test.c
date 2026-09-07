/* Synthetic PAC test binary — exercises multiple PAC instruction types
   for validating PACForge true-positive detection.
   Compile: aarch64-linux-gnu-gcc -march=armv8.3-a -static -o pac_test pac_test.c
   (The compiler will emit PAC instructions with -mbranch-protection=standard) */
#include <stdio.h>

/* Force PAC prologue/epilogue via inline asm */
void __attribute__((noinline)) func_pac_a(void) {
    asm volatile("hint #25\n"); // paciasp
    printf("func_a\n");
    asm volatile("hint #29\n"); // autiasp
}

void __attribute__((noinline)) func_pac_b(void) {
    asm volatile("hint #27\n"); // pacibsp
    printf("func_b\n");
    asm volatile("hint #31\n"); // autibsp
}

/* Signing gadget simulation */
void __attribute__((noinline)) sign_gadget(void) {
    /* pacia x0, x1 — sign x0 with context x1 using A key */
    asm volatile(
        "ldr x0, [sp, #0x10]\n"
        "ldr x1, [sp, #0x18]\n"
        ".inst 0xdac10020\n"  // pacia x0, x1
        "str x0, [sp, #0x20]\n"
    );
}

/* Oracle simulation: autia then zero-context paciza */
void __attribute__((noinline)) oracle_sim(void) {
    asm volatile(
        ".inst 0xdac11020\n"  // autia x0, x1
        ".inst 0xdac123e0\n"  // paciza x0
        "str x0, [sp, #0x30]\n"
    );
}

/* JOP-style dispatcher: set args, branch to register */
void __attribute__((noinline)) jop_dispatch(void (*fptr)(int, int, int)) {
    asm volatile(
        "mov x0, #1\n"
        "mov x1, #2\n"
        "mov x2, #3\n"
        "ldr x8, [sp, #0x40]\n"
        "br x8\n"
    );
}

/* Zero-context signing */
void __attribute__((noinline)) zero_ctx_sign(void) {
    asm volatile(".inst 0xdac123e0\n"); // paciza x0
}

/* BTI landing pad */
void __attribute__((noinline)) bti_func(void) {
    asm volatile("hint #34\n"); // bti c
    printf("bti\n");
}

int main(int argc, char **argv) {
    func_pac_a();
    func_pac_b();
    sign_gadget();
    oracle_sim();
    bti_func();
    zero_ctx_sign();
    return 0;
}
