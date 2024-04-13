/*
 * The MIT License
 *
 * Copyright 2018 Ugo Cirmignani.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dynamicVectors.h"
#include "dynamicMemory.h"
#include "../debugHelper.h"

void DYNV_VectorGeneric_Init(DYNV_VectorGenericDataType *TheVectorGeneric)
{
    TheVectorGeneric->Size = 0;
    TheVectorGeneric->Data = NULL;
    TheVectorGeneric->ElementSize = NULL;
    TheVectorGeneric->memoryTable = NULL;

    //Functions Pointers
    TheVectorGeneric->DeleteAt = &DYNV_VectorGeneric_DeleteAt;
    TheVectorGeneric->Destroy = &DYNV_VectorGeneric_Destroy;
    TheVectorGeneric->PopBack = &DYNV_VectorGeneric_PopBack;
    TheVectorGeneric->PushBack = &DYNV_VectorGeneric_PushBack;
    TheVectorGeneric->SoftDestroy = &DYNV_VectorGeneric_SoftDestroy;
    TheVectorGeneric->SoftPopBack = &DYNV_VectorGeneric_SoftPopBack;
}

void DYNV_VectorGeneric_InitWithSearchFunction(DYNV_VectorGenericDataType *TheVectorGeneric, int (*SearchFunction)(void *TheVectorGeneric, void * TheElementData))
{
    DYNV_VectorGeneric_Init(TheVectorGeneric);
    TheVectorGeneric->SearchElement = SearchFunction;
}

void DYNV_VectorGeneric_PushBack(DYNV_VectorGenericDataType *TheVectorGeneric, void * TheElementData, int TheElementSize)
{
    if (TheVectorGeneric->Data != NULL)
    {
        TheVectorGeneric->Data = (void **) DYNMEM_realloc(TheVectorGeneric->Data, sizeof(void *) * (TheVectorGeneric->Size+1), &TheVectorGeneric->memoryTable);
    }
    else
    {
        TheVectorGeneric->Data = (void **) DYNMEM_malloc (sizeof(void *) * (TheVectorGeneric->Size+1), &TheVectorGeneric->memoryTable, "pushback");
    }

    if (TheVectorGeneric->ElementSize != NULL)
    {
        TheVectorGeneric->ElementSize = (int *) DYNMEM_realloc (TheVectorGeneric->ElementSize, sizeof(int) * (TheVectorGeneric->Size+1), &TheVectorGeneric->memoryTable);
    }
    else
    {
        TheVectorGeneric->ElementSize = (int *) DYNMEM_malloc (sizeof(int), &TheVectorGeneric->memoryTable, "PushBack");
    }

    TheVectorGeneric->Data[TheVectorGeneric->Size] =  DYNMEM_malloc(TheElementSize, &TheVectorGeneric->memoryTable, "pushback");
    memcpy(TheVectorGeneric->Data[TheVectorGeneric->Size], TheElementData, TheElementSize);
    TheVectorGeneric->ElementSize[TheVectorGeneric->Size] = TheElementSize;
    TheVectorGeneric->Size++;
}

void DYNV_VectorGeneric_PopBack(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(void *TheElementToDelete))
{
    DeleteElementFunction( TheVector->Data[TheVector->Size-1]);
    DYNMEM_free(TheVector->Data[TheVector->Size-1], &TheVector->memoryTable);
    if (TheVector->Size > 1)
    {
            TheVector->Data = (void **) DYNMEM_realloc(TheVector->Data, sizeof(void *) * (TheVector->Size-1), &TheVector->memoryTable);
            TheVector->ElementSize = (int *) DYNMEM_realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1), &TheVector->memoryTable);
    }
    else
    {
            DYNMEM_free(TheVector->Data, &TheVector->memoryTable);
            DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);
            TheVector->Data = NULL;
            TheVector->ElementSize = NULL;
    }

        TheVector->Size--;
}

void DYNV_VectorGeneric_SoftPopBack(DYNV_VectorGenericDataType *TheVector)
{
    DYNMEM_free(TheVector->Data[TheVector->Size-1], &TheVector->memoryTable);

    if (TheVector->Size > 1)
    {
        TheVector->Data = (void **) DYNMEM_realloc(TheVector->Data, sizeof(void *) * (TheVector->Size-1), &TheVector->memoryTable);
        TheVector->ElementSize = (int *) DYNMEM_realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1), &TheVector->memoryTable);
    }
    else
    {
        DYNMEM_free(TheVector->Data, &TheVector->memoryTable);
        DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);
        TheVector->Data = NULL;
        TheVector->ElementSize = NULL;
    }

    TheVector->Size--;
}

void DYNV_VectorGeneric_Destroy(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(DYNV_VectorGenericDataType *TheVector))
{

	//my_printf("\n Deleting vector element %d address %ld", i,TheVector->Data[i]);
	DeleteElementFunction(TheVector);
	//DYNMEM_free(TheVector->Data[i], &TheVector->memoryTable);

    DYNMEM_free(TheVector->Data, &TheVector->memoryTable);
    DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);
    TheVector->Data = NULL;
    TheVector->ElementSize = NULL;
    TheVector->Size = 0;
}

void DYNV_VectorGeneric_SoftDestroy(DYNV_VectorGenericDataType *TheVector)
{
    int i;
    for (i = 0; i < TheVector->Size; i++)
    {
        DYNMEM_free(TheVector->Data[i], &TheVector->memoryTable);
    }
    DYNMEM_free(TheVector->Data, &TheVector->memoryTable);
    DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);

    TheVector->Data = NULL;
    TheVector->ElementSize = NULL;
    TheVector->Size = 0;
}

void DYNV_VectorGeneric_DeleteAt(DYNV_VectorGenericDataType *TheVector, int index, void (*DeleteElementFunction)(void *TheElementToDelete))
{
    int i;
    DYNV_VectorGenericDataType TempVector;
    DYNV_VectorGeneric_Init(&TempVector);

    for (i = index + 1; i < TheVector->Size; i++)
    {
        DYNV_VectorGeneric_PushBack(&TempVector, TheVector->Data[i], TheVector->ElementSize[i]);
    }

    //Permanent delete of the item At on the Heap
    DeleteElementFunction(TheVector->Data[index]);

    while (TheVector->Size > index)
    {
        DYNV_VectorGeneric_SoftPopBack(TheVector);
    }

    for (i = 0; i < TempVector.Size; i++)
    {
        DYNV_VectorGeneric_PushBack(TheVector, TempVector.Data[i], TempVector.ElementSize[i]);
    }

    DYNV_VectorGeneric_SoftDestroy(&TempVector);
}

void DYNV_VectorString_Init(DYNV_VectorString_DataType *TheVector)
{
    TheVector->Size = 0;
    TheVector->Data = NULL;
    TheVector->ElementSize = NULL;
    TheVector->memoryTable = NULL;

    //Functions Pointers
    TheVector->DeleteAt = &DYNV_VectorString_DeleteAt;
    TheVector->Destroy = &DYNV_VectorString_Destroy;
    TheVector->PopBack = &DYNV_VectorString_PopBack;
    TheVector->PushBack = &DYNV_VectorString_PushBack;
}

void DYNV_VectorString_PushBack(DYNV_VectorString_DataType *TheVector, char * TheString, int StringLenght)
{
    int i;

    if (TheVector->Data != NULL)
    {
        TheVector->Data = (char **)DYNMEM_realloc(TheVector->Data, sizeof(char *) * (TheVector->Size+1), &TheVector->memoryTable);
    }
    else
    {
        TheVector->Data = (char **) DYNMEM_malloc (sizeof(char *) * (TheVector->Size+1), &TheVector->memoryTable, "pushback");
    }

    if (TheVector->ElementSize != NULL)
    {
        TheVector->ElementSize = (int *) DYNMEM_realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size+1), &TheVector->memoryTable);
    }
    else
    {
        TheVector->ElementSize = (int *) DYNMEM_malloc (sizeof(int) * 1, &TheVector->memoryTable, "pushback");
    }

    TheVector->Data[TheVector->Size] = (char *) DYNMEM_malloc((StringLenght + 1), &TheVector->memoryTable, "pushback");

    for (i = 0; i < StringLenght; i++ )
    {
        TheVector->Data[TheVector->Size][i] = TheString[i];
    }

    TheVector->ElementSize[TheVector->Size] = i;
    TheVector->Data[TheVector->Size][TheVector->ElementSize[TheVector->Size]] = '\0';
    TheVector->Size++;
}

void DYNV_VectorString_PopBack(DYNV_VectorString_DataType *TheVector)
{
	DYNMEM_free(TheVector->Data[TheVector->Size-1], &TheVector->memoryTable);

    if (TheVector->Size > 1)
    {
        TheVector->Data = (char **)DYNMEM_realloc(TheVector->Data, sizeof(char *) * (TheVector->Size-1), &TheVector->memoryTable);
        TheVector->ElementSize = (int *) DYNMEM_realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1), &TheVector->memoryTable);
    }
    else
    {
    	DYNMEM_free(TheVector->Data, &TheVector->memoryTable);
        DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);
        TheVector->Data = NULL;
        TheVector->ElementSize = NULL;
    }

    TheVector->Size--;
}

void DYNV_VectorString_Destroy(DYNV_VectorString_DataType *TheVector)
{
    int i;
    for (i = 0; i < TheVector->Size; i++)
    {
    	DYNMEM_free(TheVector->Data[i], &TheVector->memoryTable);
    }

    if (TheVector->Data != NULL)
    	DYNMEM_free(TheVector->Data, &TheVector->memoryTable);

    if (TheVector->ElementSize != NULL)
    	DYNMEM_free(TheVector->ElementSize, &TheVector->memoryTable);

    TheVector->Data = NULL;
    TheVector->ElementSize = NULL;

    TheVector->Size = 0;
}

void DYNV_VectorString_DeleteAt(DYNV_VectorString_DataType *TheVector, int index)
{
    DYNV_VectorString_DataType TempVector;
    DYNV_VectorString_Init(&TempVector);

    for (int i = index + 1; i < TheVector->Size; i++)
    {
        DYNV_VectorString_PushBack(&TempVector, TheVector->Data[i], TheVector->ElementSize[i]);
    }

    while (TheVector->Size > index)
    {
        DYNV_VectorString_PopBack(TheVector);
    }

    for (int i = 0; i < TempVector.Size; i++)
    {
        DYNV_VectorString_PushBack(TheVector, TempVector.Data[i], TempVector.ElementSize[i]);
    }

    DYNV_VectorString_Destroy(&TempVector);
}
