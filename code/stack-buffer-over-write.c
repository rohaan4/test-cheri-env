// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <assert.h>
#include <unwind.h>

#define DEBUG_CONTEXT "Stack Buffer Over Write Compartment"
#define ERR_CODE -1

#pragma weak write_buf

void write_buf(char *buf, size_t ix)
{
    // ❌ Vulnerability: writes one byte past the end when ix == sizeof(lower)
    buf[ix] = 'b';
}

__cheri_compartment("stack-buffer-over-write")
int vuln1(void)
{
    CHERIOT_DURING
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Stack Buffer Over Write (C)...");

        char upper[0x10];
        char lower[0x10];

        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "upper = {}, lower = {}, diff = {}",
            (ptraddr_t)upper,
            (ptraddr_t)lower,
            (size_t)(upper - lower)
        );

        /* Assert that these get placed how we expect */
        assert((ptraddr_t)upper == (ptraddr_t)&lower[sizeof(lower)]);

        upper[0] = 'a';
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "upper[0] = {}", upper[0]);

        // ❌ This call will cause an out-of-bounds write on the stack
        write_buf(lower, sizeof(lower));

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "upper[0] = {}", upper[0]);

        return 0; // normal path (if no fault)
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Stack buffer over-write detected!"
        );
        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}

