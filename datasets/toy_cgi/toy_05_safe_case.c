#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "127.0.0.1";
    char command[256];

    printf("received=%s\n", ip);

    snprintf(
        command,
        sizeof(command),
        "echo NS_AEG_MARKER_START; echo safe_target=fixed; echo NS_AEG_MARKER_END"
    );

    return system(command);
}
