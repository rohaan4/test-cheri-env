// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <assert.h>
#include <unwind.h>   // for on_error()
// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Stack Buffer Over Write Compartment">;

void write_buf(char* buf, size_t ix)
{
    buf[ix] = 'b';   // ⭐ Still the vulnerability – DO NOT FIX
}

int __cheri_compartment("stack-buffer-over-write") vuln1()
{
    Debug::log("Testing Stack Buffer Over Write (C++)...");

    int result = -1;   // default return (failure)

    on_error(
        [&]() {
            char upper[0x10];
            char lower[0x10];

            Debug::log(
                "upper = {}, lower = {}, diff = {}",
                static_cast<void*>(upper),
                static_cast<void*>(lower),
                static_cast<long>(
                    reinterpret_cast<uintptr_t>(upper) -
                    reinterpret_cast<uintptr_t>(lower))
            );

            // Layout check (same as original code)
            assert((uintptr_t)upper == (uintptr_t)&lower[sizeof(lower)]);

            upper[0] = 'a';
            Debug::log("upper[0] = {}", upper[0]);

            // ⭐ Vulnerability — Out-of-bounds write
            write_buf(lower, sizeof(lower));

            Debug::log("upper[0] = {}", upper[0]);  // should not print after fault

            result = 0; // Only if no CHERI fault happened
        },

        // Error handler
        [&]() {
            Debug::log("CHERI FAULT HANDLED: Stack buffer over-write detected!");
            result = -1;
        }
    );

    return result;
}

