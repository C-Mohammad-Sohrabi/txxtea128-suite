// menu.c — interactive test runner for the xxtea128-suite
//
// Lets you pick which component to exercise and runs its own
// self-test (bench or demo). Every component must be built first:
//
//     make all        # build the original bench + all variants
//     make menu       # build this menu
//     ./menu          # run it
//
// Works on Linux, macOS and Windows (cmd.exe).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define EXT ".exe"
#else
#define EXT ""
#endif

typedef struct {
    const char *name;
    const char *path;
} entry_t;

// entry index == menu key
static const entry_t entries[] = {
    { "Original XXTEA library (speed + avalanche bench)", "bench" },
    { "variant_A - XXTEA-128 block cipher in CTR mode",   "variants/variant_A/bench_a" },
    { "variant_B - tweakable XXTEA-128",                  "variants/variant_B/bench_b" },
    { "variant_C - XXTEA-128 with round-key schedule",    "variants/variant_C/bench_c" },
    { "variant_D - Encrypt-then-MAC (bench + demo)",      "variants/variant_D/bench_etm" },
    { "variant_E - ETM with reusable context",            "variants/variant_E/bench_etm_ctx" },
    { "variant_F - ETM with associated data (demo)",      "variants/variant_F/demo_aad" },
    { "variant_G - hardened XXTEA-128",                   "variants/variant_G/bench_g" },
};
#define NENTRIES (sizeof(entries) / sizeof(entries[0]))

static void run_entry(const entry_t *e) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "./%s%s", e->path, EXT);
    printf("\n========== %s ==========\n", e->name);
    printf("running: %s\n", cmd);
    int rc = system(cmd);
    if (rc != 0) {
        printf("(!) exit code %d - binary missing? run 'make all' first\n", rc);
    }
}

static void print_menu(void) {
    printf("\n========================================================\n");
    printf("  xxtea128-suite - test menu\n");
    printf("========================================================\n");
    for (size_t i = 0; i < NENTRIES; i++) {
        printf("  %zu. %s\n", i, entries[i].name);
    }
    printf("  a. run everything\n");
    printf("  q. quit\n");
    printf("--------------------------------------------------------\n");
    printf("choice> ");
    fflush(stdout);
}

int main(void) {
    char buf[64];

    printf("xxtea128-suite - interactive test runner\n");
    printf("build everything first:  make all && make menu\n");

    for (;;) {
        print_menu();
        if (!fgets(buf, sizeof(buf), stdin)) break;

        char c = buf[0];
        if (c == 'q' || c == 'Q' || c == '\n') {
            if (c == '\n') continue;
            break;
        }
        if (c == 'a' || c == 'A') {
            for (size_t i = 0; i < NENTRIES; i++) run_entry(&entries[i]);
            continue;
        }
        if (c >= '0' && c < '0' + (int)NENTRIES) {
            run_entry(&entries[c - '0']);
            continue;
        }
        printf("unknown choice '%c' - enter 0..%zu, 'a' or 'q'\n", c, NENTRIES - 1);
    }

    printf("bye\n");
    return 0;
}