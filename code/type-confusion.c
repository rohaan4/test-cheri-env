// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>

#define DEBUG_CONTEXT "Type Confusion Compartment"
#define ERR_CODE -1

const char hello[] = "Hello World!";

union long_ptr {
    long l;
    const char *ptr;
} lp = { .ptr = hello };

void inc_long_ptr(union long_ptr *lpp)
{
    // Vulnerability — DO NOT REMOVE
    lpp->l++;
}

__cheri_compartment("type-confusion")
int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Type confusion (C)...");

    CHERIOT_DURING
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT,
            "Before inc_long_ptr: lp.ptr = {}", (char*)lp.ptr);

        // This breaks the capability (type confusion)
        inc_long_ptr(&lp);

        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT,
            "After inc_long_ptr: lp.ptr = {}", (char*)lp.ptr);
        
        return 0;
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "CHERI FAULT HANDLED: Type confusion caused capability corruption!"
        );

        return ERR_CODE;
    }
    CHERIOT_END_HANDLER
}
