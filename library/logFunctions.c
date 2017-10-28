/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <time.h>
#include "logFunctions.h"
#include <sys/time.h>
#include <stdlib.h>

void printTimeStamp(void)
{
    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    printf("\n\n %s -->",asctime( localtime(&ltime) ) );
}

void makeTimeout(struct timespec *tsp, long seconds)
{
    struct timeval now;
    /* get the current time */
    gettimeofday(&now, NULL);
    tsp->tv_sec = now.tv_sec;
    tsp->tv_nsec = now.tv_usec * 1000; /* usec to nsec */
    /* add the offset to get timeout value */
    tsp->tv_sec += seconds;
}