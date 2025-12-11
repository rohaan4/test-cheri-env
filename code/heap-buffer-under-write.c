// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Heap Buffer Under Write Compartment"
#define ERR_CODE -1

__cheri_compartment("heap-buffer-under-write")
int vuln1(void)
{
    CHERIOT_DURING
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Heap Buffer Under-write (C)...");

        int *arr = (int *)malloc(3 * sizeof(int));
        if (arr == NULL)
        {
            CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Malloc failed.");
            return ERR_CODE;
        }

        arr[0] = 10; 
        arr[1] = 20; 
        arr[2] = 30;

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting under-write arr[-1] = 999 ...");

        // ❌ VULNERABILITY — DO NOT FIX
        arr[-1] = 999;

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "arr[-1]: {} (this should not be printed).",
            arr[-1]
        );

        free(arr);
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Freed array (if we reached here).");
        return 0;
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Heap buffer under-write detected!"
        );
        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}

