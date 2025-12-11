// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Type Confusion Compartment">;

const char Hello[] = "Hello World!";

union long_ptr {
    long l;
    const char* ptr;
} lp = { .ptr = Hello };

void inc_long_ptr(long_ptr* lpp)
{
    // Vulnerability: corrupts capability tag
    lpp->l++;
}

int __cheri_compartment("type-confusion") vuln1()
{
    int result = -1; // error code

    CHERIOT_DURING
    {
        Debug::log("Testing Type confusion (C++)...");
        Debug::log("Before inc_long_ptr: lp.ptr = {}", lp.ptr);

        // Vulnerability — DO NOT FIX
        inc_long_ptr(&lp);

        Debug::log("After inc_long_ptr: lp.ptr = {}", lp.ptr);

        result = 0; // normal return if no fault
    }
    CHERIOT_HANDLER
    {
        Debug::log("CHERI FAULT HANDLED: Type confusion caused capability corruption!");
        result = -1;
    }
    CHERIOT_END_HANDLER

    return result;
}

