#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *ip = "127.0.0.1";
    char command[256];
    int ok = 0;

    if (argc > 1) {
        ip = argv[1];
    }

    for (int i = 0; i < 16; i++) {
        if (ip[i] == '\0') {
            ok = 1;
            break;
        }
    }

    if (!ok) {
        puts("NS_AEG_LENGTH_FILTERED");
        return 3;
    }

    snprintf(
        command,
        sizeof(command),
        "echo NS_AEG_MARKER_START && echo target=%s && echo NS_AEG_MARKER_END",
        ip
    );

    return system(command);
}
