#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }

    const char *ip = argv[1];
    char cmd[64];

    memcpy(cmd, ip, 32);
    cmd[32] = '\0';
    system(cmd);
    return 0;
}
