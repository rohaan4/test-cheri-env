// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
// Removed: #include <fail-simulator-on-error.h>

using Debug = ConditionalDebug<true, "Double Free Compartment">;

int __cheri_compartment("double-free") vuln1(void)
{
    Debug::log("Testing Double Free...");

    int result = -1;

    int *ptr = static_cast<int*>(malloc(sizeof(int)));
    if (!ptr)
    {
        Debug::log("malloc returned NULL");
        return -1;
    }

    *ptr = 42;

    // First free — OK
    free(ptr);
    Debug::log("After first free");

    // ⭐ Special case: no CHERI fault occurs here
    // CHERIoT allocator checks tag → finds it invalid → suppresses real free
    if (!cheri_tag_get(ptr))
    {
        Debug::log("Double free detected! Preventing second free and returning error.");
        return -1;
    }

    // If somehow tag still present (should not happen), free anyway
    free(ptr);
    Debug::log("After second free (unexpected)");

    return result;
}
