#ifndef ENABLE_PRINTF_MODULE
    #define ENABLE_PRINTF
    #ifdef ENABLE_PRINTF
        #define my_printf printf
    #else
        #define my_printf(format, ...)  // Empty macro, no action
    #endif
#endif