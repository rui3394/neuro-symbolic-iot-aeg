#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    const char *ip = argv[1];
    char cmd[16];

    /* Intentionally too small for the full benign marker. */
    snprintf(cmd, 8, "echo %s", ip);
    system(cmd);
    return 0;
}
