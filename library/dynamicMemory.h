/*
 * dynamicMemory.h
 *
 *  Created on: 22 dic 2018
 *      Author: ugo
 */

#ifndef LIBRARY_DYNAMICMEMORY_H_
#define LIBRARY_DYNAMICMEMORY_H_

typedef struct DYNMEM_MemoryTable_DataType
{
	char theName[20];
	void *address;
	size_t size;
	struct DYNMEM_MemoryTable_DataType *nextElement;
	struct DYNMEM_MemoryTable_DataType *previousElement;
	/* index of the blocks by address (dynamicMemory.c): finding the block to free or to resize does not need a walk
	   along the list. A listing of a directory with 30,000 files spent most of its time walking it: 2.7 seconds. */
	struct DYNMEM_MemoryTable_DataType *hashNext;
	/* the head of the list this block was put in (the address of the variable that was passed to DYNMEM_malloc) */
	struct DYNMEM_MemoryTable_DataType **owner;
} DYNMEM_MemoryTable_DataType;

unsigned long long int DYNMEM_GetTotalMemory(void);
unsigned long long int DYNMEM_IncreaseMemoryCounter(unsigned long long int theSize);
unsigned long long int DYNMEM_DecreaseMemoryCounter(unsigned long long int theSize);

void *DYNMEM_malloc(size_t bytes, DYNMEM_MemoryTable_DataType ** memoryListHead, char * theName);
void *DYNMEM_realloc(void *theMemoryAddress, size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead);
void  DYNMEM_free(void *f_address, DYNMEM_MemoryTable_DataType ** memoryListHead);
void  DYNMEM_freeAll(DYNMEM_MemoryTable_DataType ** memoryListHead);
void DYNMEM_dump(DYNMEM_MemoryTable_DataType *memoryListHead);

#endif /* LIBRARY_DYNAMICMEMORY_H_ */
