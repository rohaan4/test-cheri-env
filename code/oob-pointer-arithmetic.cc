// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "OOB Pointer Arithmetic Compartment">;

int __cheri_compartment("oob-pointer-arithmetic") vuln1()
{
    Debug::log("Testing Out-Of-Bounds Pointer Arithmetic (C++)...");

    int result = -1;

    on_error(
        [&]() {
            int arr[4] = {100, 200, 300, 400};

            Debug::log("Array base: {}", static_cast<void*>(arr));

            int* p = arr + 10;   // ⭐ The vulnerability — DO NOT FIX
            Debug::log("Pointer moved to arr + 10: {}", static_cast<void*>(p));

            int val = *p;        // ⭐ This triggers the CHERI bounds fault
            Debug::log("Read value: {} (this should not be printed)", val);

            result = 0;          // Only if somehow no fault occurred
        },

        [&]() {
            Debug::log("CHERI FAULT HANDLED: Out-of-bounds pointer dereference detected!");
            result = -1;
        }
    );

    return result;
}