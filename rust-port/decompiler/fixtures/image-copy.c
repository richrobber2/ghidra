/* SPDX-License-Identifier: Apache-2.0 */
/* An executable whose references to libc's optind and stderr give it
 * R_X86_64_COPY relocations. lookup, mix and unchecked read only .rodata and
 * must decompile; readopt reads the copied variable and must be rejected.
 * Built without -fpic, the table reads use absolute addresses. unchecked has
 * no index mask, so its reads leave the table. */
#include <getopt.h>
#include <stdio.h>

static const unsigned char table[16] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3};

__attribute__((noinline)) unsigned long lookup(unsigned long i) { return table[i & 15]; }

__attribute__((noinline)) unsigned long mix(unsigned long a, unsigned long b) {
    return table[a & 15] * 256 + table[b & 15];
}

__attribute__((noinline)) unsigned long unchecked(unsigned long i) { return table[i]; }

__attribute__((noinline)) unsigned long readopt(void) { return (unsigned long)optind; }

int main(int argc, char **argv) {
    fprintf(stderr, "%d", optind);
    return (int)lookup(argc) + (int)mix(argc, 2) + (int)readopt() + (int)unchecked(1) + (argv[0] != 0);
}
