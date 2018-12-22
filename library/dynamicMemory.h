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
};

void DYNMEM_Init(void);

unsigned long long int DYNMEM_GetTotalMemory(void);
unsigned long long int DYNMEM_IncreaseMemoryCounter(void);
unsigned long long int DYNMEM_DecreaseMemoryCounter(void);


void *DYNMEM_malloc(size_t bytes);
void  DYNMEM_free(void *f_address);
void  DYNMEM_freeAll(void);
void  DYNMEM_memoryInit(void);

#endif /* LIBRARY_DYNAMICMEMORY_H_ */
