/* AethroSync — ui.h — colour UI declarations */
#pragma once
#ifndef MPCP_UI_H
#define MPCP_UI_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* =============================================================
 * ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗
 * ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝
 * ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗
 * ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝
 * ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗
 * ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝
 *  MPCP Purple UI — ANSI true-colour terminal theme
 * ============================================================= */

/* Colour detection: set NO_COLOR=1 or UI_NO_COLOUR=1 to disable */

/* True-colour ANSI macros */
#define C_PLUM    "\033[38;2;200;150;255m"   /* bright violet       */
#define C_VIOLET  "\033[38;2;160;100;220m"   /* medium purple       */
#define C_GRAPE   "\033[38;2;110;60;170m"    /* deep purple         */
#define C_ORCHID  "\033[38;2;180;120;240m"   /* orchid              */
#define C_WHITE   "\033[38;2;230;220;255m"   /* soft white          */
#define C_GREY    "\033[38;2;130;120;150m"   /* muted grey          */
#define C_LIME    "\033[38;2;140;255;160m"   /* success green       */
#define C_ROSE    "\033[38;2;255;100;110m"   /* error red           */
#define C_GOLD    "\033[38;2;255;220;100m"   /* warning amber       */
#define C_CYAN    "\033[38;2;100;220;255m"   /* info cyan           */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_BLINK   "\033[5m"
#define C_NOCURSOR "\033[?25l"
#define C_CURSOR   "\033[?25h"

/* Particle/glow characters */
#define GLYPH_DOT   "\xc2\xb7"          /* · middle dot         */
#define GLYPH_STAR  "\xe2\x98\x85"      /* ★ black star         */
#define GLYPH_LOCK  "\xf0\x9f\x94\x92" /* 🔒 padlock (UTF-8)   */
#define GLYPH_BOLT  "\xe2\x9a\xa1"      /* ⚡ lightning         */
#define GLYPH_OK    "\xe2\x9c\x93"      /* ✓ check              */
#define GLYPH_FAIL  "\xe2\x9c\x97"      /* ✗ cross              */
#define GLYPH_ARR   "\xe2\x86\x92"      /* → arrow              */
#define GLYPH_WAVE  "\xe2\x88\xbf"      /* ∿ sine wave          */
#define GLYPH_SKULL "\xe2\x98\xa0"      /* ☠ tripwire warning   */
#define GLYPH_GEM   "\xe2\x97\x86"      /* ◆ diamond            */

static void ui_sleep_ms(int ms)
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

static void __attribute__((unused)) ui_colour_init(void)
{
    const char *term   = getenv("TERM");
    const char *no_col = getenv("NO_COLOR");
    const char *ui_no  = getenv("UI_NO_COLOUR");
    g_ui_colour = isatty(STDOUT_FILENO)
                  && no_col == NULL && ui_no == NULL
                  && term != NULL && strcmp(term, "dumb") != 0;
}

/* ── PARTICLE BURST: tiny sparks scatter when the logo lands ── */
static void ui_particle_burst(void)
{
    if (!g_ui_colour) return;
    static const char *sparks[] = {
        "\xe2\x80\xa2", /* • */
        "\xe2\x81\x82", /* ⁂ */
        "\xc2\xb7",     /* · */
        "\xe2\x97\x8c", /* ◌ */
        "\xe2\x97\xa6", /* ◦ */
    };
    const char *cols[] = {
        "\033[38;2;200;150;255m",
        "\033[38;2;160;80;220m",
        "\033[38;2;130;60;190m",
        "\033[38;2;240;180;255m",
        "\033[38;2;100;40;160m",
    };
    /* Print 3 rows of drifting sparks */
    for (int row = 0; row < 3; row++) {
        printf("  ");
        for (int col = 0; col < 36; col++) {
            int si = (row * 7 + col * 3) % 5;
            if ((row + col) % 3 == 0)
                printf("%s%s%s", cols[si % 5], sparks[si], C_RESET);
            else
                printf(" ");
        }
        printf("\n");
        fflush(stdout);
        ui_sleep_ms(40);
    }
}

/* ── GLOW PULSE: line that throbs bright→dim once ── */
static void ui_glow_line(int width)
{
    if (!g_ui_colour) { printf("\n"); return; }
    /* Bright pass */
    printf("  %s", C_PLUM);
    for (int i = 0; i < width; i++) printf("\xe2\x94\x80");
    printf("%s", C_RESET);
    fflush(stdout);
    ui_sleep_ms(60);
    /* Dim pass (rewrite same line) */
    printf("\r  %s", C_GRAPE);
    for (int i = 0; i < width; i++) printf("\xe2\x94\x80");
    printf("%s\n", C_RESET);
    fflush(stdout);
}

/* ── LOGO: gradient line-by-line reveal then particle burst ── */
static void __attribute__((unused)) ui_print_logo(void)
{
    static const char *logo[] = {
        "           /\\_/\\ *                    *        *                    ",
        "     *    ( o.o )     *        *                        *           ",
        "           > - <                                  *                 ",
        "         _        _   _              ____                           ",
        "        / \\   ___| |_| |__  _ __ ___/ ___| _   _ _ __   ___    *   ",
        " *     / _ \\ / _ \\ __| '_ \\| '__/ _ \\___ \\| | | | '_ \\ / __|       ",
        "      / ___ \\  __/ |_| | | | | | (_) |__) | |_| | | | | (__      * ",
        "     /_/   \\_\\__|\\__|_| |_|_|  \\___/____/ \\__, |_| |_|\\___|       ",
        "  *                                        |___/                    ",
        "                                        *            *        *     ",
        "       *     *      *         *      _                              ",
        "         *                *       _\\( )/_      *                    ",
        "                                   /(O)\\                            ",
    };
    static const char *grad[] = {
        "\033[38;2;80;40;120m",
        "\033[38;2;95;48;140m",
        "\033[38;2;110;55;160m",
        "\033[38;2;130;70;185m",
        "\033[38;2;150;85;205m",
        "\033[38;2;165;95;215m",
        "\033[38;2;175;105;225m",
        "\033[38;2;185;115;235m",
        "\033[38;2;195;128;245m",
        "\033[38;2;200;135;250m",
        "\033[38;2;205;142;252m",
        "\033[38;2;208;150;254m",
        "\033[38;2;210;160;255m",
    };
    int n = 13;
    printf("\n");
    if (g_ui_colour) printf(C_NOCURSOR);

    for (int i = 0; i < n; i++) {
        if (g_ui_colour) printf("%s", grad[i]);
        printf("%s", logo[i]);
        if (g_ui_colour) printf("%s", C_RESET);
        printf("\n");
        fflush(stdout);
        ui_sleep_ms(55);
    }

    /* Subtitle with lock glyph */
    if (g_ui_colour) {
        printf("  %s" GLYPH_LOCK "  %sMulti-Port Catch Protocol%s  %sv0.5%s\n",
               C_PLUM, C_VIOLET, C_RESET, C_GREY, C_RESET);
    } else {
        printf("  Multi-Port Catch Protocol  v0.5\n");
    }

    ui_glow_line(38);
    ui_particle_burst();

    if (g_ui_colour) printf(C_CURSOR);
}


#endif /* MPCP_UI_H */
