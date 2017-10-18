
#ifndef DYNAMIC_VECTORS_H
#define	DYNAMIC_VECTORS_H

#ifdef	__cplusplus
extern "C" {
#endif

struct DYNV_VectorString
{
    char **Data;
    int Size;
    int *ElementSize;
    void (*PushBack)(void *TheVector, char * TheString, int StringLenght);
    void (*PopBack)(void *TheVector);
    void (*Destroy)(void *TheVector);
    void (*DeleteAt)(void *TheVector, int index);
} typedef DYNV_VectorString_DataType;

struct DYNV_VectorGenericDataStruct
{
    void **Data;
    int Size;
    int *ElementSize;
    void (*PushBack)(void *TheVectorGeneric, void * TheElementData, int TheElementSize);
    void (*PopBack)(void *TheVector, void (*DeleteElement)(void *TheElementToDelete));
    void (*SoftPopBack)(void *TheVector);
    void (*Destroy)(void *TheVector, void (*DeleteElement)(void *TheElementToDelete));
    void (*SoftDestroy)(void *TheVector);
    void (*DeleteAt)(void *TheVector, int index, void (*DeleteElement)(void *TheElementToDelete));
    int  (*SearchElement)(void *TheVectorGeneric, void * TheElementData);
} typedef DYNV_VectorGenericDataType;


void DYNV_VectorString_Init(DYNV_VectorString_DataType *TheVector);
void DYNV_VectorString_PushBack(DYNV_VectorString_DataType *TheVector, char * TheString, int StringLenght);
void DYNV_VectorString_PopBack(DYNV_VectorString_DataType *TheVector);
void DYNV_VectorString_Destroy(DYNV_VectorString_DataType *TheVector);
void DYNV_VectorString_DeleteAt(DYNV_VectorString_DataType *TheVector, int index);
void DYNV_VectorGeneric_Init(DYNV_VectorGenericDataType *TheVectorGeneric);
void DYNV_VectorGeneric_InitWithSearchFunction(DYNV_VectorGenericDataType *TheVectorGeneric, int (*SearchFunction)(void *TheVectorGeneric, void * TheElementData));
void DYNV_VectorGeneric_PushBack(DYNV_VectorGenericDataType *TheVectorGeneric, void * TheElementData, int TheElementSize);
void DYNV_VectorGeneric_PopBack(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(void *TheElementToDelete));
void DYNV_VectorGeneric_SoftPopBack(DYNV_VectorGenericDataType *TheVector);
void DYNV_VectorGeneric_Destroy(DYNV_VectorGenericDataType *TheVector, void (*DeleteElementFunction)(void *TheElementToDelete));
void DYNV_VectorGeneric_SoftDestroy(DYNV_VectorGenericDataType *TheVector);
void DYNV_VectorGeneric_DeleteAt(DYNV_VectorGenericDataType *TheVector, int index, void (*DeleteElementFunction)(void *TheElementToDelete));

#ifdef	__cplusplus
}
#endif

#endif	/* DYNAMIC_VECTORS_H */

