/*
 * dynamicMemory.c
 *
 *  Created on: 22 dic 2018
 *      Author: ugo
 */

#include <stdio.h>
#include <stdlib.h>
#define _REENTRANT
#include <pthread.h>
#include <string.h>
#include "dynamicMemory.h"
#include "errorHandling.h"
#include "../debugHelper.h"

// --- GLOBALS ---

// Total memory allocated (Global Counter)
static unsigned long long int theTotalMemory = 0;

// Mutex for the global counter
static pthread_mutex_t memoryCountMutex = PTHREAD_MUTEX_INITIALIZER;

// Mutex for the linked list operations
// (Added to prevent race conditions when modifying next/prev pointers)
static pthread_mutex_t memoryListMutex = PTHREAD_MUTEX_INITIALIZER;

// --- HELPER FUNCTIONS ---

unsigned long long int DYNMEM_GetTotalMemory(void)
{
    pthread_mutex_lock(&memoryCountMutex);
    unsigned long long int mem = theTotalMemory;
    pthread_mutex_unlock(&memoryCountMutex);
    return mem;
}

unsigned long long int DYNMEM_IncreaseMemoryCounter(unsigned long long int theSize)
{
    pthread_mutex_lock(&memoryCountMutex);
    theTotalMemory += theSize;
    unsigned long long int ret = theTotalMemory;
    pthread_mutex_unlock(&memoryCountMutex);
    return ret;
}

unsigned long long int DYNMEM_DecreaseMemoryCounter(unsigned long long int theSize)
{
    pthread_mutex_lock(&memoryCountMutex);
    // Prevent underflow check could be added here
    theTotalMemory -= theSize;
    unsigned long long int ret = theTotalMemory;
    pthread_mutex_unlock(&memoryCountMutex);
    return ret;
}

// --- INDEX OF THE BLOCKS BY ADDRESS ---
// Every function below runs it with memoryListMutex held.

#include <stdint.h>

static DYNMEM_MemoryTable_DataType **hashBuckets = NULL;
static size_t hashBucketCount = 0;
static size_t hashNodeCount = 0;

static size_t hashSlot(const void *address, size_t bucketCount)
{
    uintptr_t x = (uintptr_t)address;

    x ^= x >> 17;
    x *= (uintptr_t)0x9E3779B97F4A7C15ULL;
    return (size_t)((x >> 16) & (bucketCount - 1));
}

static void hashGrow(void)
{
    size_t newCount = (hashBucketCount == 0) ? 1024 : hashBucketCount * 2;
    DYNMEM_MemoryTable_DataType **newBuckets = (DYNMEM_MemoryTable_DataType **)calloc(newCount, sizeof(*newBuckets));

    if (newBuckets == NULL)
        return;                         // it goes on with the longer chains

    for (size_t i = 0; i < hashBucketCount; i++)
    {
        DYNMEM_MemoryTable_DataType *node = hashBuckets[i];

        while (node != NULL)
        {
            DYNMEM_MemoryTable_DataType *next = node->hashNext;
            size_t slot = hashSlot(node->address, newCount);

            node->hashNext = newBuckets[slot];
            newBuckets[slot] = node;
            node = next;
        }
    }

    free(hashBuckets);
    hashBuckets = newBuckets;
    hashBucketCount = newCount;
}

static void hashInsert(DYNMEM_MemoryTable_DataType *node)
{
    if (hashBucketCount == 0 || hashNodeCount >= hashBucketCount * 2)
        hashGrow();

    if (hashBucketCount == 0)
    {
        node->hashNext = NULL;          // no index at all (no memory): the walk of the list finds it
        return;
    }

    size_t slot = hashSlot(node->address, hashBucketCount);

    node->hashNext = hashBuckets[slot];
    hashBuckets[slot] = node;
    hashNodeCount++;
}

static DYNMEM_MemoryTable_DataType *hashFind(const void *address)
{
    if (hashBucketCount == 0)
        return NULL;

    for (DYNMEM_MemoryTable_DataType *node = hashBuckets[hashSlot(address, hashBucketCount)]; node != NULL; node = node->hashNext)
    {
        if (node->address == address)
            return node;
    }

    return NULL;
}

static void hashRemove(DYNMEM_MemoryTable_DataType *node)
{
    if (hashBucketCount == 0)
        return;

    DYNMEM_MemoryTable_DataType **link = &hashBuckets[hashSlot(node->address, hashBucketCount)];

    while (*link != NULL)
    {
        if (*link == node)
        {
            *link = node->hashNext;
            node->hashNext = NULL;
            hashNodeCount--;
            return;
        }

        link = &(*link)->hashNext;
    }
}

/* The block of this address that belongs to the list `head`, or NULL. The index finds it at once; a block put in the
   list by another variable that held the same head (a copy of the structure that has the list) is looked for along
   the list, as it always was. */
static DYNMEM_MemoryTable_DataType *findBlock(void *address, DYNMEM_MemoryTable_DataType **head)
{
    DYNMEM_MemoryTable_DataType *node = hashFind(address);

    if (node != NULL && node->owner == head)
        return node;

    for (DYNMEM_MemoryTable_DataType *temp = *head; temp != NULL; temp = temp->nextElement)
    {
        if (temp->address == address)
            return temp;
    }

    return NULL;
}

// --- CORE FUNCTIONS ---

void *DYNMEM_malloc(size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead, char * theName)
{
    void *memory = NULL;
    DYNMEM_MemoryTable_DataType *newItem = NULL;

    // 1. Allocation (done outside lock for concurrency performance)
    memory = calloc(bytes, 1);
    if (!memory)
    {
        report_error_q("Memory allocation error, out of memory.", __FILE__, __LINE__, 0);
        return NULL;
    }

    newItem = calloc(1, sizeof(DYNMEM_MemoryTable_DataType));
    if (!newItem)
    {
        free(memory); // Rollback
        report_error_q("Memory allocation error, no room for memory list item.", __FILE__, __LINE__, 0);
        return NULL;
    }

    // 2. Prepare Metadata
    newItem->address = memory;
    newItem->owner = memoryListHead;
    newItem->size = bytes;
    strncpy(newItem->theName, theName, sizeof(newItem->theName) - 1);
    newItem->theName[sizeof(newItem->theName) - 1] = '\0';

    // 3. Critical Section: Update List
    pthread_mutex_lock(&memoryListMutex);

    newItem->nextElement = *memoryListHead;
    newItem->previousElement = NULL;

    if ((*memoryListHead) != NULL)
    {
        (*memoryListHead)->previousElement = newItem;
    }
    *memoryListHead = newItem;
    hashInsert(newItem);

    pthread_mutex_unlock(&memoryListMutex);

    // 4. Update Global Counter
    DYNMEM_IncreaseMemoryCounter(bytes + sizeof(DYNMEM_MemoryTable_DataType));

    return memory;
}

void *DYNMEM_realloc(void *theMemoryAddress, size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead)
{
    if (theMemoryAddress == NULL)
    {
        return DYNMEM_malloc(bytes, memoryListHead, "Realloc");
    }

    DYNMEM_MemoryTable_DataType *temp = NULL;
    DYNMEM_MemoryTable_DataType *found = NULL;

    // 1. Critical Section: Find the metadata FIRST
    pthread_mutex_lock(&memoryListMutex);
    
    (void)temp;
    found = findBlock(theMemoryAddress, memoryListHead);

    if (!found)
    {
        pthread_mutex_unlock(&memoryListMutex);
        report_error_q("Unable to reallocate memory not previously allocated", __FILE__, __LINE__, 0);
        return NULL;
    }

    // 2. Perform System Realloc (While holding list lock to prevent free race, 
    //    or unlock here if you accept the risk to gain performance. 
    //    Holding it is safer.)
    
    void *newMemory = realloc(theMemoryAddress, bytes);

    if (newMemory)
    {
        // Calculation for global counter update
        size_t oldSize = found->size;
        
        // Update node (and its place in the index: the address may have changed)
        hashRemove(found);
        found->address = newMemory;
        found->size = bytes;
        hashInsert(found);
        
        pthread_mutex_unlock(&memoryListMutex);

        // Update Globals
        if (bytes > oldSize)
            DYNMEM_IncreaseMemoryCounter(bytes - oldSize);
        else
            DYNMEM_DecreaseMemoryCounter(oldSize - bytes);

        return newMemory;
    }
    else
    {
        // Realloc failed. Old memory block is still valid.
        pthread_mutex_unlock(&memoryListMutex);
        report_error_q("Memory reallocation error, out of memory.", __FILE__, __LINE__, 0);
        // Do NOT return NULL if you want to act like standard realloc? 
        // Actually standard realloc returns NULL on failure, leaving old block. 
        return NULL; 
    }
}

void DYNMEM_free(void *f_address, DYNMEM_MemoryTable_DataType **memoryListHead)
{
    if (f_address == NULL) return;

    DYNMEM_MemoryTable_DataType *temp = NULL;
    DYNMEM_MemoryTable_DataType *found = NULL;

    // 1. Critical Section: Search and Unlink
    pthread_mutex_lock(&memoryListMutex);

    (void)temp;
    found = findBlock(f_address, memoryListHead);

    if (!found)
    {
        pthread_mutex_unlock(&memoryListMutex);
        report_error_q("Unable to free memory not previously allocated", __FILE__, __LINE__, 1);
        return;
    }

    // Unlink from list
    if (found->previousElement)
        found->previousElement->nextElement = found->nextElement;

    if (found->nextElement)
        found->nextElement->previousElement = found->previousElement;

    if (found == (*memoryListHead))
        (*memoryListHead) = found->nextElement;

    hashRemove(found);

    pthread_mutex_unlock(&memoryListMutex);

    // 2. Update Counter and Free
    DYNMEM_DecreaseMemoryCounter(found->size + sizeof(DYNMEM_MemoryTable_DataType));
    
    free(found->address); // Free actual memory
    free(found);          // Free metadata
}

void DYNMEM_freeAll(DYNMEM_MemoryTable_DataType **memoryListHead)
{
    DYNMEM_MemoryTable_DataType *current = NULL;
    DYNMEM_MemoryTable_DataType *next = NULL;
    unsigned long long int totalSizeRemoved = 0;

    // 1. Critical Section: Wipe entire list
    pthread_mutex_lock(&memoryListMutex);

    current = *memoryListHead;
    while (current != NULL)
    {
        next = current->nextElement;

        totalSizeRemoved += (current->size + sizeof(DYNMEM_MemoryTable_DataType));

        hashRemove(current);
        free(current->address);
        free(current);

        current = next;
    }
    
    *memoryListHead = NULL;

    pthread_mutex_unlock(&memoryListMutex);

    // 2. Update Global Counter Once
    if (totalSizeRemoved > 0)
    {
        DYNMEM_DecreaseMemoryCounter(totalSizeRemoved);
    }
}

void DYNMEM_dump(DYNMEM_MemoryTable_DataType *memoryListHead)
{
    int count = 0;
    unsigned long long int total = 0;

    // Dump is read-only, but we need to lock to prevent the list 
    // changing while we print (segfault prevention).
    pthread_mutex_lock(&memoryListMutex);

    my_printf("\n==== DYNMEM Memory Dump ====\n");

    for (DYNMEM_MemoryTable_DataType *current = memoryListHead; current != NULL; current = current->nextElement)
    {
        my_printf("Block %d:\n", count + 1);
        my_printf("  Address   : %p\n", current->address);
        my_printf("  Size      : %zu bytes\n", current->size);
        my_printf("  Label     : %s\n", current->theName);
        my_printf("  Block MetaSize: %zu bytes\n", sizeof(DYNMEM_MemoryTable_DataType));
        total += current->size + sizeof(DYNMEM_MemoryTable_DataType);
        count++;
    }

    pthread_mutex_unlock(&memoryListMutex);

    my_printf("\nTotal blocks      : %d\n", count);
    my_printf("Total memory used : %llu bytes (including metadata)\n", total);
    my_printf("Global counter    : %llu bytes\n", DYNMEM_GetTotalMemory());
    my_printf("=============================\n");
}