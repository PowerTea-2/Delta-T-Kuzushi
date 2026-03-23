/* AethroSync — src/main.c — int main() */
#include "../include/platform.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdatomic.h>
#include <sodium.h>
#include <zstd.h>
#include "../include/mpcp.h"

#include "../include/ui.h"


int main(int argc, char **argv)
{
    mpcp_winsock_init(); /* no-op on Linux */
    if (argc == 2 && strcmp(argv[1], "--check-config") == 0) {
        mpcp_config_t cfg;
        mpcp_config_defaults(&cfg);
        int rc = mpcp_config_load_default(&cfg);
        if (rc == MPCP_OK) {
            printf("Config OK\n");
            mpcp_config_dump(&cfg, stdout);
        } else {
            fprintf(stderr, "Config error: %d\n", rc);
        }
        return rc == MPCP_OK ? 0 : 1;
    }

    if (argc == 2 && strcmp(argv[1], "--test") == 0)
        return main_test();
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        if (mpcp_crypto_init() != MPCP_OK) { fprintf(stderr, "crypto init failed\n"); return 1; }
        int r1 = main_test();
        int r2 = run_selftest();
        return (r1 == 0 && r2 == 0) ? 0 : 1;
    }
    if (argc == 2 && strcmp(argv[1], "--bench") == 0) {
        if (mpcp_crypto_init() != MPCP_OK) { fprintf(stderr, "crypto init failed\n"); return 1; }
        return run_bench();
    }

    if (mpcp_crypto_init() != MPCP_OK) {
        mpcp_perror("init", MPCP_ERR_CRYPTO);
        return 1;
    }

    contacts_load();

    ui_colour_init();
    ui_print_logo();

    for (;;) {
        if (g_ui_colour) {
            printf("  %s┌─────────────────────────┐%s\n",
                   C_GRAPE, C_RESET);
            printf("  %s│%s  %s" GLYPH_STAR " MENU " GLYPH_STAR "%s"
                   "                  %s│%s\n",
                   C_GRAPE,C_RESET, C_PLUM,C_RESET, C_GRAPE,C_RESET);
            printf("  %s├─────────────────────────┤%s\n",
                   C_GRAPE, C_RESET);
            printf("  %s│%s  %s1%s  " GLYPH_BOLT "  Send / Receive a file"
                   "   %s│%s\n", C_GRAPE,C_RESET, C_PLUM,C_RESET, C_GRAPE,C_RESET);
            printf("  %s│%s  %s2%s  " GLYPH_STAR "  Manage contacts"
                   "         %s│%s\n", C_GRAPE,C_RESET, C_PLUM,C_RESET, C_GRAPE,C_RESET);
            printf("  %s│%s  %s3%s  " GLYPH_WAVE "  Run self-test"
                   "            %s│%s\n", C_GRAPE,C_RESET, C_PLUM,C_RESET, C_GRAPE,C_RESET);
            printf("  %s│%s  %s4%s  " GLYPH_GEM "  Benchmark"
                   "                %s│%s\n", C_GRAPE,C_RESET, C_PLUM,C_RESET, C_GRAPE,C_RESET);
            printf("  %s│%s  %sq%s     Quit"
                   "                    %s│%s\n", C_GRAPE,C_RESET, C_VIOLET,C_RESET, C_GRAPE,C_RESET);
            printf("  %s└─────────────────────────┘%s\n\n",
                   C_GRAPE, C_RESET);
        } else {
            printf("\n  1) Send / Receive a file\n");
            printf("  2) Manage contacts\n");
            printf("  3) Run self-test (loopback)\n");
            printf("  4) Benchmark (loopback throughput)\n");
            if (g_ui_colour)
                printf("  %s5%s  %sâ¡%s  Listen / server mode\n",
                       C_PLUM, C_RESET, C_GOLD, C_RESET);
            else
                printf("  5) Listen / server mode\n");
            printf("  q) Quit\n\n");
        }

        char buf[8];
        read_line("Choice", buf, sizeof(buf));

        if (buf[0] == '1') {
            int rc = run_transfer();
            if (rc != 0) {
                if (g_ui_colour)
                    printf("\n  %s" GLYPH_FAIL " Session ended with errors.%s\n", C_ROSE, C_RESET);
                else
                    printf("\n  Session ended with errors.\n");
            }
        } else if (buf[0] == '2') {
            cmd_contacts();
        } else if (buf[0] == '3') {
            run_selftest();
        } else if (buf[0] == '4') {
            run_bench();
        } else if (buf[0] == '5') {
            run_listen_once();
        } else if (buf[0] == 'q' || buf[0] == 'Q') {
            if (g_ui_colour)
                printf("\n  %s" GLYPH_GEM " Bye.%s\n\n", C_VIOLET, C_RESET);
            else
                printf("Bye.\n");
            return 0;
        } else {
            if (g_ui_colour)
                printf("  %sUnknown option.%s\n", C_GREY, C_RESET);
            else
                printf("  Unknown option.\n");
        }
    }
}

