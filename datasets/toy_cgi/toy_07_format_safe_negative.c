#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    const char *ip = argv[1];
    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "user input: %s", ip);
    system("echo SAFE_FIXED");
    return 0;
}
