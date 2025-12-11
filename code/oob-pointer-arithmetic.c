// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>

#define DEBUG_CONTEXT "OOB Pointer Arithmetic Compartment"
#define ERR_CODE -1

__cheri_compartment("oob-pointer-arithmetic")
int vuln1(void)
{
    CHERIOT_DURING
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Testing Out-Of-Bounds Pointer Arithmetic (C)..."
        );

        int arr[4] = {100, 200, 300, 400};
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Array base: {}",
            (uintptr_t)arr
        );

        /* Make a pointer well past the end via arithmetic */
        int *p = arr + 10; // ❌ Out-of-bounds pointer
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Pointer moved to arr + 10: {}",
            (uintptr_t)p
        );

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Dereferencing OOB pointer ..."
        );

        // ❌ Vulnerability — DO NOT FIX
        int val = *p;

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Read value: {} (this should not be printed)",
            val
        );

        return 0; // Only reached if no fault occurs
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Out-of-bounds pointer dereference detected!"
        );
        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}

