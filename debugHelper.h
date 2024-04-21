#ifndef ENABLE_PRINTF_MODULE

    // Uncomment next line to enable debug printf
    //#define ENABLE_PRINTF
    //#define ENABLE_PRINTF_ERROR

    #ifdef ENABLE_PRINTF 
        #define my_printf(fmt, args...) fprintf(stderr, " file: %s  %d  %s()" fmt, __FILE__, __LINE__, __func__, ##args)
        #else
        #define my_printf(format, ...)  // Empty macro, no action
    #endif

    #ifdef ENABLE_PRINTF_ERROR 
        #define my_printfError(fmt, args...) fprintf(stderr, " file: %s  %d  %s()" fmt, __FILE__, __LINE__, __func__, ##args)
        #else
        #define my_printfError(format, ...)  // Empty macro, no action
    #endif
#endif