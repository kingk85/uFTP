/*
 * dynamicMemory.c
 *
 *  Created on: 22 dic 2018
 *      Author: ugo
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "dynamicMemory.h"
#include "errorHandling.h"

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
	return theTotalMemory;
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

void *DYNMEM_malloc(size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead)
{
	void *memory = NULL;
	DYNMEM_MemoryTable_DataType *newItem = NULL;
	memory = calloc(bytes,1);
	newItem = calloc(1, sizeof(DYNMEM_MemoryTable_DataType));

	printf("Allocating new item in memory, size of %d", bytes);

	if(memory)
	{
		if(newItem == NULL)
		{
			report_error_q("Memory allocation error, no room for memory list item.",__FILE__,__LINE__, 0);
		}

		DYNMEM_IncreaseMemoryCounter(bytes + sizeof(DYNMEM_MemoryTable_DataType));

		newItem->address = memory;
		newItem->size = bytes;
		newItem->nextElement = NULL;
		newItem->previousElement = NULL;

		if( (*memoryListHead) != NULL)
		{
			newItem->nextElement = *memoryListHead;
			(*memoryListHead)->previousElement = newItem;
			(*memoryListHead) = newItem;
		}
		else
		{
			//printf("\nmemoryListHead = %ld", (int) *memoryListHead);
			*memoryListHead = newItem;
			//printf("\nmemoryListHead = newItem %ld", (int) *memoryListHead);
		}

		//printf("\nElement size: %ld", (*memoryListHead)->size);
		//printf("\nElement address: %ld", (long int) (*memoryListHead)->address);
		//printf("\nElement nextElement: %ld",(long int) (*memoryListHead)->nextElement);
		//printf("\nElement previousElement: %ld",(long int) (*memoryListHead)->previousElement);

		return memory;
	}
	else
	{
		report_error_q("Memory allocation error, out of memory.", __FILE__,__LINE__,0);
		return NULL;
	}
}

void *DYNMEM_realloc(void *theMemoryAddress, size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead)
{
	void *newMemory = NULL;
	newMemory = realloc(theMemoryAddress, bytes);

	//printf("Reallocating item in memory, size of %d", bytes);

	if(newMemory)
	{
		DYNMEM_MemoryTable_DataType *temp = NULL,*found = NULL;
		for( temp = (*memoryListHead); temp!=NULL; temp = temp->nextElement)
		{
			if(temp->address == theMemoryAddress)
			{
				found = temp;
				break;
			}
		}

		if(!found)
		{
			report_error_q("Unable to free memory not previously allocated",__FILE__,__LINE__, 0);
			// Report this as an error
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

		//printf("\nElement size: %ld", (*found)->size);
		//printf("\nElement address: %ld", (long int) (*found)->address);
		//printf("\nElement nextElement: %ld",(long int) (*found)->nextElement);
		//printf("\nElement previousElement: %ld",(long int) (*found)->previousElement);

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
		//Debug TRAP
		//char *theData ="c";
		//strcpy(theData, "ciaociaociao");
		report_error_q("Unable to free memory not previously allocated",__FILE__,__LINE__, 1);
		// Report this as an error
	}

	DYNMEM_DecreaseMemoryCounter(found->size + sizeof(DYNMEM_MemoryTable_DataType));

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
	printf("\nDYNMEM_freeAll called");
	printf("\nElement size: %ld", (*memoryListHead)->size);
	printf("\nElement address: %ld", (long int) (*memoryListHead)->address);
	printf("\nElement nextElement: %ld",(long int) (*memoryListHead)->nextElement);
	printf("\nElement previousElement: %ld",(long int) (*memoryListHead)->previousElement);

	DYNMEM_MemoryTable_DataType *temp = NULL;
	while((*memoryListHead) != NULL)
	{
		printf("\nFree table element");
		free((*memoryListHead)->address);
		temp = (*memoryListHead)->nextElement;
		free((*memoryListHead));
		(*memoryListHead) = temp;
	}
}
