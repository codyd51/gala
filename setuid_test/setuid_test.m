#include <stddef.h>
#include <stdbool.h>

#include <stdio.h>

#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

void print_now(void) {
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    printf("%s", asctime(timeinfo));
}

int main(int argc, const char** argv) {
    printf("Attempting setuid...\n");
    int a = setuid(0);
    printf("returned %d\n", a);

    const char* paths[] = {
        "/var/mobile/foo",
        "/etc/test",
    };
    int pathCount = 2;

    while (1) {
        print_now();
        for (int i = 0; i < pathCount; i++) {
            const char* path = paths[i];
            printf("\tPoking %s... ", path);
            FILE* f = fopen(path, "w");
            if (!f) {
                printf("INACCESSIBLE\n");
            }
            else {
                printf("Accessible\n");
            }
        }
        printf("\n");

        sleep(5);
    }
    return 0;
}
