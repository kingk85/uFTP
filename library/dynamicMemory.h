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
	void *address;
	size_t size;
	struct DYNMEM_MemoryTable_DataType *nextElement;
	struct DYNMEM_MemoryTable_DataType *previousElement;
} DYNMEM_MemoryTable_DataType;

unsigned long long int DYNMEM_GetTotalMemory(void);
unsigned long long int DYNMEM_IncreaseMemoryCounter(unsigned long long int theSize);
unsigned long long int DYNMEM_DecreaseMemoryCounter(unsigned long long int theSize);

void  DYNMEM_Init(void);
void *DYNMEM_malloc(size_t bytes, DYNMEM_MemoryTable_DataType ** memoryListHead);
void *DYNMEM_realloc(void *theMemoryAddress, size_t bytes, DYNMEM_MemoryTable_DataType **memoryListHead);
void  DYNMEM_free(void *f_address, DYNMEM_MemoryTable_DataType ** memoryListHead);
void  DYNMEM_freeAll(DYNMEM_MemoryTable_DataType ** memoryListHead);


#endif /* LIBRARY_DYNAMICMEMORY_H_ */
