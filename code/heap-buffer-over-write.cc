// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>     // for on_error()

// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Heap Buffer Over Write Compartment">;

int __cheri_compartment("heap-buffer-over-write") vuln1()
{
    Debug::log("Testing Heap Buffer Over-write (C++)...");

    int result = -1;   // default error return

    on_error(
        [&]() {
            int* arr = new int[3];
            if (!arr) {
                Debug::log("Allocation failed!");
                result = -1;
                return;
            }

            arr[0] = 1;
            arr[1] = 2;
            arr[2] = 3;

            Debug::log("Attempting to write arr[10] (out-of-bounds)...");

            // ⭐ Vulnerability: DO NOT FIX
            arr[10] = 999;

            Debug::log("Write completed (this should NOT be printed).");
            Debug::log("Value of written element: {}", arr[10]);

            delete[] arr;
            result = 0;
        },
        [&]() {
            // This executes after the CHERI fault is generated
            Debug::log("CHERI FAULT HANDLED: Heap buffer over-write detected!");
            result = -1;
        }
    );

    return result;
}

