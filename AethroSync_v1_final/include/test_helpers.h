/* AethroSync — include/test_helpers.h — shared test macros */
#pragma once
#ifndef MPCP_TEST_HELPERS_H
#define MPCP_TEST_HELPERS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* Shared test counters — defined in tests/test_core.c */
extern int tests_run;
extern int tests_passed;
extern int tests_failed;

/* Core test macros */
#define PASS(name) do { \
    printf("  [PASS] %s\n", (name)); \
    tests_passed++; tests_run++; \
} while(0)

#define FAIL(name, reason) do { \
    printf("  [FAIL] %s: %s\n", (name), (reason)); \
    tests_failed++; tests_run++; \
} while(0)

#define CHECK(name, expr) do { \
    if (expr) PASS(name); \
    else FAIL(name, #expr " was false"); \
} while(0)

#endif /* MPCP_TEST_HELPERS_H */
