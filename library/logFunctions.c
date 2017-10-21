/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <time.h>
#include "logFunctions.h"


void printTimeStamp(void)
{
    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    printf("\n\n %s -->",asctime( localtime(&ltime) ) );
}