#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dynamicVectors.h"

void DYNV_VectorGeneric_Init(DYNV_VectorGenericDataType *TheVectorGeneric)
{
    TheVectorGeneric->Size = 0;
    TheVectorGeneric->Data = NULL;
    TheVectorGeneric->ElementSize = NULL;

    //Functions Pointers
    TheVectorGeneric->DeleteAt = (void *)DYNV_VectorGeneric_DeleteAt;
    TheVectorGeneric->Destroy = (void *)DYNV_VectorGeneric_Destroy;
    TheVectorGeneric->PopBack = (void *)DYNV_VectorGeneric_PopBack;
    TheVectorGeneric->PushBack = (void *)DYNV_VectorGeneric_PushBack;
    TheVectorGeneric->SoftDestroy = (void *)DYNV_VectorGeneric_SoftDestroy;
    TheVectorGeneric->SoftPopBack = (void *)DYNV_VectorGeneric_SoftPopBack;
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
        TheVectorGeneric->Data = (void **) realloc(TheVectorGeneric->Data, sizeof(void *) * (TheVectorGeneric->Size+1));
        }
    else
        {
        TheVectorGeneric->Data = (void **) malloc (sizeof(void *) * (TheVectorGeneric->Size+1));
        }

    if (TheVectorGeneric->ElementSize != NULL)
        {
        TheVectorGeneric->ElementSize = (int *) realloc (TheVectorGeneric->ElementSize, sizeof(int) * (TheVectorGeneric->Size+1));
        }
    else
        {
        TheVectorGeneric->ElementSize = (int *) malloc (sizeof(int));
        }

    TheVectorGeneric->Data[TheVectorGeneric->Size] = (void *) calloc(1, TheElementSize);

    memcpy(TheVectorGeneric->Data[TheVectorGeneric->Size], TheElementData, TheElementSize);

    TheVectorGeneric->ElementSize[TheVectorGeneric->Size] = TheElementSize;
    TheVectorGeneric->Size++;
}

void DYNV_VectorGeneric_PopBack(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(void *TheElementToDelete))
{
    DeleteElementFunction((void *) TheVector->Data[TheVector->Size-1]);
    free(TheVector->Data[TheVector->Size-1]);
    if (TheVector->Size > 1)
    	{
            TheVector->Data = (void **) realloc(TheVector->Data, sizeof(void *) * (TheVector->Size-1));
            TheVector->ElementSize = (int *) realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1));
    	}
    else
    	{
            free(TheVector->Data);
            free(TheVector->ElementSize);
            TheVector->Data = NULL;
            TheVector->ElementSize = NULL;
    	}

    TheVector->Size--;
}

void DYNV_VectorGeneric_SoftPopBack(DYNV_VectorGenericDataType *TheVector)
	{
	free(TheVector->Data[TheVector->Size-1]);

	if (TheVector->Size > 1)
		{
		TheVector->Data = (void **) realloc(TheVector->Data, sizeof(void *) * (TheVector->Size-1));
		TheVector->ElementSize = (int *) realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1));
		}
	else
		{
		free(TheVector->Data);
		free(TheVector->ElementSize);
		TheVector->Data = NULL;
		TheVector->ElementSize = NULL;
		}

	TheVector->Size--;
	}

void DYNV_VectorGeneric_Destroy(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(void *TheElementToDelete))
{
    int i;
    for (i = 0; i < TheVector->Size; i++)
    {
    DeleteElementFunction((void *) TheVector->Data[i]);
    free(TheVector->Data[i]);
    }

    free(TheVector->Data);
    free(TheVector->ElementSize);

    TheVector->Data = NULL;
    TheVector->ElementSize = NULL;

    TheVector->Size = 0;
}

void DYNV_VectorGeneric_SoftDestroy(DYNV_VectorGenericDataType *TheVector)
	{
	int i;
	for (i = 0; i < TheVector->Size; i++)
		{
		free(TheVector->Data[i]);
		}

	free(TheVector->Data);
	free(TheVector->ElementSize);

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
	DeleteElementFunction((void *) TheVector->Data[index]);

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

    //Functions Pointers
    TheVector->DeleteAt = (void *)DYNV_VectorString_DeleteAt;
    TheVector->Destroy = (void *)DYNV_VectorString_Destroy;
    TheVector->PopBack = (void *)DYNV_VectorString_PopBack;
    TheVector->PushBack = (void *)DYNV_VectorString_PushBack;
}

void DYNV_VectorString_PushBack(DYNV_VectorString_DataType *TheVector, char * TheString, int StringLenght)
	{
	int i;

	if (TheVector->Data != NULL)
		{
		TheVector->Data = (char **)realloc(TheVector->Data, sizeof(char *) * (TheVector->Size+1));
		}
	else
		{
		TheVector->Data = (char **) malloc (sizeof(char *) * (TheVector->Size+1));
		}

	if (TheVector->ElementSize != NULL)
		{
		TheVector->ElementSize = (int *) realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size+1));
		}
	else
		{
		TheVector->ElementSize = (int *) malloc (sizeof(int) * 1);
		}

	TheVector->Data[TheVector->Size] = (char *) calloc(sizeof(char), StringLenght + 1);

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
	free(TheVector->Data[TheVector->Size-1]);

	if (TheVector->Size > 1)
		{
		TheVector->Data = (char **)realloc(TheVector->Data, sizeof(char *) * (TheVector->Size-1));
		TheVector->ElementSize = (int *) realloc (TheVector->ElementSize, sizeof(int) * (TheVector->Size-1));
		}
	else
		{
		free(TheVector->Data);
		free(TheVector->ElementSize);
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
		free(TheVector->Data[i]);
		}

	free(TheVector->Data);
	free(TheVector->ElementSize);

	TheVector->Data = NULL;
	TheVector->ElementSize = NULL;

	TheVector->Size = 0;
	}

void DYNV_VectorString_DeleteAt(DYNV_VectorString_DataType *TheVector, int index)
	{
	int i;
	DYNV_VectorString_DataType TempVector;
	DYNV_VectorString_Init(&TempVector);

	for (i = index + 1; i < TheVector->Size; i++)
		{
		DYNV_VectorString_PushBack(&TempVector, TheVector->Data[i], TheVector->ElementSize[i]);
		}

	while (TheVector->Size > index)
		{
		DYNV_VectorString_PopBack(TheVector);
		}

	for (i = 0; i < TempVector.Size; i++)
		{
		DYNV_VectorString_PushBack(TheVector, TempVector.Data[i], TempVector.ElementSize[i]);
		}

	DYNV_VectorString_Destroy(&TempVector);
	}
