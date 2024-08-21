#include <stdio.h>
#include <stdlib.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define LOG(format, ...) printf(ANSI_COLOR_CYAN "%s:%d " format ANSI_COLOR_RESET "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ERROR(format, ...) printf(ANSI_COLOR_RED "%s:%d " format ANSI_COLOR_RESET "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define WARN(format, ...) printf(ANSI_COLOR_YELLOW "%s:%d " format ANSI_COLOR_RESET "\n", __FILE__, __LINE__, ##__VA_ARGS__)