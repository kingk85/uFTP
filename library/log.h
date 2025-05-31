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

#ifndef LOG_H
#define LOG_H

#define LOG_INFO_PREFIX "[INFO] "
#define LOG_DEBUG_PREFIX "[DEBUG] "
#define LOG_ERROR_PREFIX "[ERROR] "
#define LOG_SECURITY_PREFIX "[SECURITY] "

#define LOG(msg) logMessage(msg, __FILE__, __LINE__, __func__)
#define LOG_INFO(msg) logMessage(LOG_INFO_PREFIX msg, __FILE__, __LINE__, __func__)
#define LOG_DEBUG(msg) logMessage(LOG_DEBUG_PREFIX msg, __FILE__, __LINE__, __func__)
#define LOG_ERROR(msg) logMessage(LOG_ERROR_PREFIX msg, __FILE__, __LINE__, __func__)
#define LOG_SECURITY(msg) logMessage(LOG_SECURITY_PREFIX msg, __FILE__, __LINE__, __func__)
#define LOGF(fmt, ...) logMessagef(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

int logInit(const char* folder, int numberOfLogFiles);
void logMessage(const char* message, const char* file, int line, const char* function);
void logMessagef(const char* file, int line, const char* function, const char* fmt, ...);

#endif