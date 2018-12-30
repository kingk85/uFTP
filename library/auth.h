/*
 * auth.h
 *
 *  Created on: 30 dic 2018
 *      Author: ugo
 */

#ifndef LIBRARY_AUTH_H_
#define LIBRARY_AUTH_H_

#include "ftpData.h"

void loginCheck(char *name, char *password, loginDataType *login, DYNMEM_MemoryTable_DataType **memoryTable);
int authenticateSystem(const char *username, const char *password);

#endif /* LIBRARY_AUTH_H_ */
