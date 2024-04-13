#ifndef ENABLE_PRINTF_MODULE
    #define ENABLE_PRINTF
    #ifdef ENABLE_PRINTF
        #define my_printf(fmt, args...) fprintf(stderr, " file: %s  %d  %s()" fmt, __FILE__, __LINE__, __func__, ##args)
        #else
        #define my_printf(format, ...)  // Empty macro, no action
    #endif
#endif