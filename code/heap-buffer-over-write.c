// Copyright Microsoft and CHERiOT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Heap Buffer Over Write Compartment"
#define ERR_CODE -1

/// Thread entry point for the compartment.
__cheri_compartment("heap-buffer-over-write")
int vuln1(void)
{
    CHERIOT_DURING
    {
        int* arr = (int*)malloc(3 * sizeof(int));
        if (arr == NULL)
        {
            CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Malloc failed.");
            return ERR_CODE;
        }

        arr[0] = 1;
        arr[1] = 2;
        arr[2] = 3;

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Buffer Over-write (C)...");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting to write arr[4]...");

        // ⭐ Vulnerability — DO NOT FIX
        arr[4] = 999;

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "arr[4]: {} (This should not be printed).",
            arr[4]
        );

        free(arr);
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT,
            "This line may not be reached if program crashes."
        );

        return 0; // Normal return if no fault happens
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Heap buffer over-write detected!"
        );
        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}

