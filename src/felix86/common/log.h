#include <stdio.h>
#include <stdlib.h>

#define LOG(format, ...) printf("%s@%d " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ERROR(format, ...) printf("%s@%d " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); exit(1)
