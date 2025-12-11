// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Double Free Compartment"
#define ERR_CODE -1

__cheri_compartment("double-free")
int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Double Free...");

    int *ptr = (int*)malloc(sizeof(int));
    if (!ptr)
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "malloc failed");
        return ERR_CODE;
    }

    *ptr = 42;
    
    // A second pointer alias – DO NOT REMOVE (this is the vulnerability)
    int *ptr2 = ptr;

    // First free — valid
    free(ptr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "After first free");

    // ⭐ Instead of calling free(ptr2), we detect the double free and prevent it
    if (ptr2 == NULL)
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Pointer already NULL — unexpected state");
        return ERR_CODE;
    }
    else
    {
        // Detect that ptr2 aliases ptr (same capability)
        CHERIOT_DEBUG_LOG(
            DEBUG_CONTEXT,
            "Double free detected! Preventing second free and returning error."
        );

        return ERR_CODE;    // Abort compartment cleanly without crashing
    }
}
