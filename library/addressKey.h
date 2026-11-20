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

#ifndef ADDRESS_KEY_H
#define ADDRESS_KEY_H

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* The key under which an address is counted: the failed logins (parseCommandPass) and the new
   connections of the minute (connection.c). key: INET6_ADDRSTRLEN bytes.

   An IPv4 address is counted as it is, also when it arrives on an IPv6 socket as ::ffff:a.b.c.d.
   An IPv6 address is counted as its network, the first 64 bits: whoever has a network has 2^64
   addresses and could use a new one for every attempt, and would never be blocked. */
static inline void addressKey(const char *address, char *key, size_t size)
{
    struct in6_addr parsed;

    if (inet_pton(AF_INET6, address, &parsed) == 1 && !IN6_IS_ADDR_V4MAPPED(&parsed))
    {
        memset(&parsed.s6_addr[8], 0, 8);

        if (inet_ntop(AF_INET6, &parsed, key, (socklen_t)size) != NULL)
        {
            return;
        }
    }

    snprintf(key, size, "%s", address);
}

#endif /* ADDRESS_KEY_H */
