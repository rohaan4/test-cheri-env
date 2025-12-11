// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Use After Free Compartment">;

int __cheri_compartment("use-after-free") vuln1()
{
    Debug::log("Testing Use-After-Free (C++)...");

    int result = -1;

    on_error(
        [&]() {
            int* ptr = new int;
            if (!ptr)
            {
                Debug::log("Allocation failed!");
                result = -1;
                return;
            }

            *ptr = 123;
            Debug::log("ptr capability: {}", static_cast<void*>(ptr));
            Debug::log("ptr points to memory with value: {}", *ptr);

            delete ptr;
            Debug::log("Memory has been freed.");

            // ⭐ Vulnerability — DO NOT FIX
            *ptr = 456;  
            Debug::log("Value is now: {} (this should not be printed)", *ptr);

            result = 0; // would only happen if no fault occurs
        },

        [&]() {
            Debug::log("CHERI FAULT HANDLED: Use-after-free detected!");
            result = -1;
        }
    );

    return result;
}
