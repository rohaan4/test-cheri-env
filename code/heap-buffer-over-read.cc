// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>    // for on_error()
#include <stdlib.h>

// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Heap Buffer Over Read Compartment">;

int __cheri_compartment("heap-buffer-over-read") vuln1()
{
    Debug::log("Running Buffer Over-read (C++)...");

    int result = -1;   // error code

    on_error(
        [&]() {
            int* arr = new int[3];
            if (arr == nullptr)
            {
                Debug::log("Allocation failed!");
                result = -1;
                return;
            }

            Debug::log("Array created, assigning values...");
            arr[0] = 10;
            arr[1] = 20;
            arr[2] = 30;

            Debug::log("Accessing arr[10] (out-of-bounds)...");
            int value = arr[10];  // ⭐ Vulnerability kept on purpose
            Debug::log("Value: {} (should NOT print)", value);

            delete[] arr;
            Debug::log("Completed unexpectedly without fault...");
            result = 0;
        },
        [&]() {
            // This runs if CHERI triggers a fault inside the above lambda
            Debug::log("CHERI FAULT HANDLED: Heap buffer over-read detected!");
            result = -1;
        }
    );

    return result;
}

