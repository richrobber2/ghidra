/* SPDX-License-Identifier: Apache-2.0 */
/* Built with -fstack-protector-all: every function checks the %fs:0x28 canary
 * and calls __stack_chk_fail through the PLT on a mismatch. checked and
 * asserted also abort through abort() and assert(); prints calls an import
 * that returns and must be rejected. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define F __attribute__((noinline, visibility("default"))) uint64_t

F local_table(uint64_t a, uint64_t b) {
    volatile uint64_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = a * (uint64_t)i + b;
    return buf[a & 7] ^ buf[b & 7];
}

F checked(uint64_t a, uint64_t b) {
    if (a == 0xdead) abort();
    return a + b;
}

F asserted(uint64_t a, uint64_t b) {
    assert(a != 7);
    return a * b;
}

F prints(uint64_t a, uint64_t b) {
    puts("prints");
    return a + b;
}
