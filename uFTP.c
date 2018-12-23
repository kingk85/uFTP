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

/*
void myFunction (void * p);
void myFunction2 (void * p);
void myFunction3 (void * p);
void myFunction4 (void **p);

void myFunction (void * p)
{
	static int i2 = 11;
	myFunction2(p);
	p = &i2;
	printf("\n1 p = %lld address of the pointer is %lld", p, &p);
	printf(" intval %d", *(int *) p);
}

void myFunction2 (void * p)
{
	myFunction3(p);
	printf("\n2 p = %lld address of the pointer is %lld", p, &p);
	printf(" intval %d", *(int *) p);
}

void myFunction3 (void * p)
{
	printf("\n3 p = %lld address of the pointer is %lld", p, &p);
	printf(" intval %d", *(int *) p);
}

void myFunction4 (void **p)
{
	static int oraSi = 12;
	printf("\n4 p = %lld address of the pointer is %lld", *p, &*p);
	printf(" intval %d", *(int *) *p);

	*p = &oraSi;
	myFunction5(&*p);
}

void myFunction5 (void **p)
{
	static int oraSi = 13;
	printf("\n5 p = %lld address of the pointer is %lld", *p, &*p);
	printf(" intval %d", *(int *) *p);

	*p = &oraSi;
}
*/

#include <stdio.h>
#include <stdlib.h>
#include "ftpServer.h"

int main(int argc, char** argv) 
{
	/*
	void *p;
	int a = 10;
	p = (void *)&a;

	printf("\np at init = %lld address of the pointer is %lld", p, &p);
	//myFunction(p);
	printf("\np after myFunction = %lld address of the pointer is %lld", p, &p);
	myFunction4(&p);
	printf("\np after myFunction4 = %lld address of the pointer is %lld", p, &p);
	printf(" intval %d", *(int *) p);
	exit(0);
*/
    runFtpServer();
    return (EXIT_SUCCESS);
}
