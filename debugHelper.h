#ifndef ENABLE_PRINTF_MODULE

    // Uncomment next line to enable debug printf
    #define ENABLE_PRINTF
    #define ENABLE_PRINTF_ERROR

    #define CURRENT_FILE __FILE__
    #define CURRENT_LINE __LINE__
    #define CURRENT_FUNC __func__

    #ifdef ENABLE_PRINTF 
        #define my_printf(fmt, args...) fprintf(stderr, " - file: %s - # %d - %s()" fmt, CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC, ##args)
        #else
        #define my_printf(format, ...)  // Empty macro, no action
    #endif

    #ifdef ENABLE_PRINTF_ERROR 
        #define my_printfError(fmt, args...) fprintf(stderr, " - file: - # %s - %d - %s()" fmt, CURRENT_FILE, CURRENT_LINE, CURRENT_FUNC, ##args)
        #else
        #define my_printfError(format, ...)  // Empty macro, no action
    #endif
#endif