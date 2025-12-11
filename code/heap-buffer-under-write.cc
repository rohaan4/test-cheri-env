// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>      // for on_error()

// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Heap Buffer Under Write Compartment">;

int __cheri_compartment("heap-buffer-under-write") vuln1()
{
    Debug::log("Testing Heap Buffer Under-write (C++)...");

    int result = -1; // default failure

    on_error(
        [&]() {
            int* arr = new int[3];
            if (!arr)
            {
                Debug::log("Allocation failed!");
                result = -1;
                return;
            }

            arr[0] = 10;
            arr[1] = 20;
            arr[2] = 30;

            Debug::log("Attempting under-write arr[-1] = 999 ...");

            // ⭐ Vulnerability — do NOT fix
            arr[-1] = 999;

            Debug::log("Under-write completed (this should NOT be printed).");
            Debug::log("Inserted element: {}", arr[-1]);

            delete[] arr;
            result = 0; // only if no CHERI fault occurs
        },
        [&]() {
            Debug::log("CHERI FAULT HANDLED: Heap buffer under-write detected!");
            result = -1;
        }
    );

    return result;
}
