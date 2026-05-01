#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *ip = "127.0.0.1";
    char command[256];

    if (argc > 1) {
        ip = argv[1];
    }

    snprintf(
        command,
        sizeof(command),
        "echo NS_AEG_MARKER_START && echo target=%s && echo NS_AEG_MARKER_END",
        ip
    );

    return system(command);
}
