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
#include <termios.h>
#include <unistd.h>

#include "ftpServer.h"
#include "library/openSsl.h"

#define HASH_PASSWORD_OPTION "--hash-password"
#define PASSWORD_INPUT_SIZE 256

/* One line without the end of line. With a terminal the typed characters are not shown. */
static int readPasswordLine(const char *prompt, char *buffer, size_t size)
{
    struct termios original, silent;
    int isTerminal = isatty(STDIN_FILENO);
    int ok;

    if (isTerminal)
    {
        fputs(prompt, stderr);
        tcgetattr(STDIN_FILENO, &original);
        silent = original;
        silent.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent);
    }

    ok = fgets(buffer, (int)size, stdin) != NULL;

    if (isTerminal)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        fputc('\n', stderr);
    }

    if (ok)
        buffer[strcspn(buffer, "\r\n")] = '\0';

    return ok;
}

/* ./uFTP --hash-password [--iterations N]
   Prints the line to put in uftpd.cfg instead of the password (PASSWORD_n = <line>). The
   password is asked twice on a terminal; from a pipe it is the first line of the input. */
static int hashPasswordCommand(int argc, char **argv)
{
    int iterations = PASSWORD_HASH_DEFAULT_ITERATIONS;
    char password[PASSWORD_INPUT_SIZE], repeated[PASSWORD_INPUT_SIZE], hash[PASSWORD_HASH_BUFFER_SIZE];

    for (int i = 2; i < argc; i++)
    {
        char *end = NULL;
        long value;

        if (strcmp(argv[i], "--iterations") != 0 || i + 1 >= argc)
        {
            fprintf(stderr, "usage: %s %s [--iterations N]\n", argv[0], HASH_PASSWORD_OPTION);
            return 2;
        }

        value = strtol(argv[++i], &end, 10);
        if (*argv[i] == '\0' || *end != '\0' || value < 1 || value > PASSWORD_HASH_MAX_ITERATIONS)
        {
            fprintf(stderr, "uFTP: the iterations must be a number from 1 to %d\n", PASSWORD_HASH_MAX_ITERATIONS);
            return 2;
        }
        iterations = (int)value;
    }

    if (!readPasswordLine("Password: ", password, sizeof(password)) || password[0] == '\0')
    {
        fprintf(stderr, "uFTP: the password is empty\n");
        return 1;
    }

    if (isatty(STDIN_FILENO) &&
        (!readPasswordLine("Repeat the password: ", repeated, sizeof(repeated)) || strcmp(password, repeated) != 0))
    {
        fprintf(stderr, "uFTP: the two passwords are not the same\n");
        return 1;
    }

    if (!passwordHashCreate(password, iterations, hash, sizeof(hash)))
    {
        fprintf(stderr, "uFTP: the hash can not be made (hashed passwords need a build of uFTP with OpenSSL)\n");
        return 1;
    }

    printf("%s\n", hash);
    return 0;
}

int main(int argc, char** argv) 
{
    if (argc > 1 && strcmp(argv[1], HASH_PASSWORD_OPTION) == 0)
    {
        return hashPasswordCommand(argc, argv);
    }

    runFtpServer();
    return EXIT_SUCCESS;
}
