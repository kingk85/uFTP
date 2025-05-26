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

//total memory allocated
static unsigned long long int theTotalMemory;
static pthread_mutex_t memoryCountMutex;

void DYNMEM_Init(void)
{
	static int state = 0;

	if(state != 0)
		return;

	state = 1;

	theTotalMemory = 0;

    if (pthread_mutex_init(&memoryCountMutex, NULL) != 0)
    {
    	report_error_q("Unable to init the mutex", __FILE__, __LINE__, 0);
    }
}

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
	theTotalMemory = theTotalMemory + theSize;
	pthread_mutex_unlock(&memoryCountMutex);
	return theTotalMemory;
}

unsigned long long int DYNMEM_DecreaseMemoryCounter(unsigned long long int theSize)
{
	pthread_mutex_lock(&memoryCountMutex);
	theTotalMemory = theTotalMemory - theSize;
	pthread_mutex_unlock(&memoryCountMutex);
	return theTotalMemory;
}

void *DYNMEM_malloc(size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead, char * theName)
{
	void *memory = NULL;
	DYNMEM_MemoryTable_DataType *newItem = NULL;
	memory = calloc(bytes,1);
	newItem = calloc(1, sizeof(DYNMEM_MemoryTable_DataType));
	//my_printf("Allocating new item in memory, size of %d", bytes);

	if(memory)
	{
		if(newItem == NULL)
		{
			report_error_q("Memory allocation error, no room for memory list item.",__FILE__,__LINE__, 0);
			free(memory);
			return NULL;
		}

		DYNMEM_IncreaseMemoryCounter(bytes + sizeof(DYNMEM_MemoryTable_DataType));

		newItem->address = memory;
		newItem->size = bytes;
		newItem->nextElement = NULL;
		newItem->previousElement = NULL;
		strncpy(newItem->theName, theName, sizeof(newItem->theName) - 1);
		newItem->theName[sizeof(newItem->theName) - 1] = '\0';

		if( (*memoryListHead) != NULL)
		{
			newItem->nextElement = *memoryListHead;
			(*memoryListHead)->previousElement = newItem;
			(*memoryListHead) = newItem;
		}
		else
		{
			//my_printf("\nmemoryListHead = %ld", (int) *memoryListHead);
			*memoryListHead = newItem;
			//my_printf("\nmemoryListHead = newItem %ld", (int) *memoryListHead);
		}

//		my_printf("\nElement size: %ld", (*memoryListHead)->size);
//		my_printf("\nElement address: %ld", (long int) (*memoryListHead)->address);
//		my_printf("\nElement nextElement: %ld",(long int) (*memoryListHead)->nextElement);
//		my_printf("\nElement previousElement: %ld",(long int) (*memoryListHead)->previousElement);

		return memory;
	}
	else
	{
		if(newItem)
			free(newItem);
		report_error_q("Memory allocation error, out of memory.", __FILE__,__LINE__,0);
		return NULL;
	}
}

void *DYNMEM_realloc(void *theMemoryAddress, size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead)
{
	void *newMemory = NULL;
	//my_printf("\nSearching address %lld", theMemoryAddress);
	newMemory = realloc(theMemoryAddress, bytes);

	//my_printf("\nReallocating item in memory, size of %d", bytes);
	//my_printf("\nSearching address %lld", theMemoryAddress);
	//my_printf("(*memoryListHead) = %lld", (*memoryListHead));

	if(newMemory)
	{
		DYNMEM_MemoryTable_DataType *temp = NULL,*found = NULL;
		for( temp = (*memoryListHead); temp!=NULL; temp = temp->nextElement)
		{
			//my_printf("\n %lld == %lld", temp->address, theMemoryAddress);
			if(temp->address == theMemoryAddress)
			{
				found = temp;
				break;
			}
		}

		if(!found)
		{
			//Debug TRAP
			//char *theData ="c";
			//strcpy(theData, "NOOOOOOOOOOOOOOOO");

			report_error_q("Unable to reallocate memory not previously allocated",__FILE__,__LINE__, 0);
			// Report this as an error
			return NULL;
		}

		if (found->size > bytes)
		{
			DYNMEM_DecreaseMemoryCounter((found->size-bytes));
		}
		else if (found->size < bytes)
		{
			DYNMEM_IncreaseMemoryCounter((bytes-found->size));
		}

		found->address = newMemory;
		found->size = bytes;

		//my_printf("\nElement size: %ld", (*found)->size);
		//my_printf("\nElement address: %ld", (long int) (*found)->address);
		//my_printf("\nElement nextElement: %ld",(long int) (*found)->nextElement);
		//my_printf("\nElement previousElement: %ld",(long int) (*found)->previousElement);

		return newMemory;
	}
	else
	{
		report_error_q("Memory reallocation error, out of memory.", __FILE__,__LINE__,0);
		return NULL;
	}
}

void DYNMEM_free(void *f_address, DYNMEM_MemoryTable_DataType ** memoryListHead)
{
	DYNMEM_MemoryTable_DataType *temp = NULL,*found = NULL;

	if(f_address == NULL)
		return;

	for(temp=(*memoryListHead); temp!=NULL; temp = temp->nextElement)
	{
		if(temp->address == f_address)
		{
			found = temp;
			break;
		}
	}

	if(!found)
	{
		//my_printf("\n\nMemory address : %ld not found\n\n", f_address);
		//Debug TRAP
		//char *theData ="c";
		//strcpy(theData, "ciaociaociao");
		report_error_q("Unable to free memory not previously allocated",__FILE__,__LINE__, 1);
		// Report this as an error

		return;
	}

	DYNMEM_DecreaseMemoryCounter(found->size + sizeof(DYNMEM_MemoryTable_DataType));


	//my_printf("\nFree of %ld", f_address);

	free(f_address);
	if(found->previousElement)
		found->previousElement->nextElement = found->nextElement;

	if(found->nextElement)
		found->nextElement->previousElement = found->previousElement;

	if(found == (*memoryListHead))
		(*memoryListHead) = found->nextElement;

	free(found);
}

void DYNMEM_freeAll(DYNMEM_MemoryTable_DataType **memoryListHead)
{

	DYNMEM_MemoryTable_DataType *temp = NULL;

	while((*memoryListHead) != NULL)
	{
//		my_printf("\nDYNMEM_freeAll called");
//		my_printf("\nElement size: %ld", (*memoryListHead)->size);
//		my_printf("\nElement address: %ld", (long int) (*memoryListHead)->address);
//		my_printf("\nElement nextElement: %ld",(long int) (*memoryListHead)->nextElement);
//		my_printf("\nElement previousElement: %ld",(long int) (*memoryListHead)->previousElement);

		DYNMEM_DecreaseMemoryCounter((*memoryListHead)->size + sizeof(DYNMEM_MemoryTable_DataType));
		//my_printf("\nFree table element");
		free((*memoryListHead)->address);
		temp = (*memoryListHead)->nextElement;
		free((*memoryListHead));
		(*memoryListHead) = temp;
	}
}

void DYNMEM_dump(DYNMEM_MemoryTable_DataType *memoryListHead)
{
    int count = 0;
    unsigned long long int total = 0;

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

    my_printf("\nTotal blocks      : %d\n", count);
    my_printf("Total memory used : %llu bytes (including metadata)\n", total);
    my_printf("Global counter    : %llu bytes\n", DYNMEM_GetTotalMemory());
    my_printf("=============================\n");
}
