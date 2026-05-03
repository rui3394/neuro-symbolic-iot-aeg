#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    const char *ip = argv[1];
    char cmd[128];

    snprintf(cmd, sizeof(cmd), "echo %s", ip);
    system(cmd);
    return 0;
}
