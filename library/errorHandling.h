/*
 * errorHandling.h
 *
 *  Created on: 22 dic 2018
 *      Author: ugo
 */

#ifndef LIBRARY_ERRORHANDLING_H_
#define LIBRARY_ERRORHANDLING_H_

void report_error_q(const char *msg, const char *file,int line_no, int use_perror);
void report_error(const char *msg, const char *file, int line_no, intuse_perror);



#endif /* LIBRARY_ERRORHANDLING_H_ */
