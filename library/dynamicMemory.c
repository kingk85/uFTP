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

//total memory allocated
static unsigned long long int theTotalMemory;

void DYNMEM_Init(void)
{
	theTotalMemory = 0;
}

unsigned long long int DYNMEM_GetTotalMemory(void)
{
	return theTotalMemory;
}

unsigned long long int DYNMEM_IncreaseMemoryCounter(void)
{
	return theTotalMemory;
}
unsigned long long int DYNMEM_DecreaseMemoryCounter(void)
{
	return theTotalMemory;
}

void * DYNMEM_malloc(size_t bytes)
{
	void *memory = NULL;

	DYNMEM_MemoryTable_DataType *new_item = NULL;

	memory = calloc(bytes,1);
	new_item = calloc(1,sizeof(struct memory_list));
	if(memory)
	{
		if(new_item == NULL)
		{
			report_error_q("Memory allocation error, no room for memory list item.",
			__FILE__,__LINE__, 0);
		}

	global_memory_count += bytes + sizeof(struct memory_list);

	new_item->address = memory;
	new_item->size = bytes;
	new_item->next = NULL;
	new_item->prev = NULL;
	if(memory_list_head) {
	new_item->next = memory_list_head;
	memory_list_head->prev = new_item;
	memory_list_head = new_item;
	} else {
	memory_list_head = new_item;
	}
	return memory;
	} else {
	report_error_q("Memory allocation error, out of memory.",
	__FILE__,__LINE__,0);
	return NULL;
	}
}

void DYNMEM_free(void *f_address) {
memory_list *temp = NULL,*found = NULL;
if(f_address == NULL)
return;
for(temp=memory_list_head;temp!=NULL;temp = temp->next) {
if(temp->address == f_address) {
found = temp;
break;
}
}
if(!found) {
report_error_q("Unable to free memory not previously allocated",
__FILE__,__LINE__,0);
// Report this as an error
}
global_memory_count -= found->size + sizeof(struct memory_list);
free(f_address);
if(found->prev)
found->prev->next = found->next;
if(found->next)
found->next->prev = found->prev;
if(found == memory_list_head)
memory_list_head = found->next;
free(found);
}


void DYNMEM_freeAll(void) {
memory_list *temp = NULL;
while(memory_list_head) {
free(memory_list_head->address);
309Chapter 13
temp = memory_list_head->next;
free(memory_list_head);
memory_list_head = temp;
}
}
void DYNMEM_memoryInit(void) {
static int state = 0;
if(state != 0)
return;
state = 1;
memory_list_head = NULL;
global_memory_count = 0;
atexit(w_free_all);
}

