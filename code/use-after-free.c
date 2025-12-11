// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Use After Free Compartment"
#define ERR_CODE -1

/// Thread entry point.
__cheri_compartment("use-after-free")
int vuln1()
{
    CHERIOT_DURING
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Use-After-Free (C)...");

        int* ptr = (int*)malloc(sizeof(int));
        if (ptr == NULL)
        {
            CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "malloc failed.");
            return ERR_CODE;
        }

        *ptr = 123;
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "ptr points to memory with value: {}",
            *ptr
        );

        free(ptr);
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Memory has been freed.");

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Attempting to dereference dangling pointer... "
        );

        // ❌ Vulnerability — DO NOT FIX
        *ptr = 456;

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Value is now: {} (this should not be printed)",
            *ptr
        );

        return 0; // Only if no fault occurs
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Use-after-free detected!"
        );
        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}