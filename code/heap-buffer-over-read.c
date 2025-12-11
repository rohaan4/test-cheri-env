// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Heap Buffer Over Read Compartment"
#define ERR_CODE -1

/// Thread entry point.
__cheri_compartment("heap-buffer-over-read")
int vuln1()
{
    volatile int retval = 0; // must be volatile because used across try/catch

    CHERIOT_DURING
    {
        int* arr = (int*)malloc(3 * sizeof(int));
        if (arr == NULL)
        {
            CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Malloc failed.");
            retval = ERR_CODE;
            cleanup_unwind();   // force handler path
        }

        arr[0] = 10;
        arr[1] = 20;
        arr[2] = 30;

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Buffer Over-read (C)...");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Accessing arr[10]...");

        // ⭐ Vulnerability: Do NOT fix it.
        int value = arr[10];

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT,
                          "Value: {} (should not print if fault handled)",
                          value);

        free(arr);
        retval = 0;   // success path
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Heap buffer over-read detected!"
        );
        retval = ERR_CODE;
    }
    CHERIOT_END_HANDLER

    return retval;
}
