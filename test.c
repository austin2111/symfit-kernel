#include <stdio.h>
#include <sys/mman.h>

int main() {
    printf("Protect arg is %d\n", PROT_READ | PROT_WRITE);
    printf("Flags arg is %d\n", MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED);
    int retval = mmap ((void *)0x10001000, 8, 3, 50, -1, 0);
    printf("DEBUG: Return value was %d\n", retval);
    return 0;
}
