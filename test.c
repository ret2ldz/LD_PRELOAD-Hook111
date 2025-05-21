#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("[*]Test App: Starting...\n");

    printf("[*]Test App: Allocating memory (p1)...\n");
    char *p1 = (char*)malloc(10);
    if (p1) {
        strcpy(p1, "hello");
        printf("Test App: p1 content: %s\n", p1);
    } else {
        printf("Test App: malloc for p1 failed.\n");
    }

    printf("[*]Test App: Allocating memory (p2)...\n");
    void *p2 = malloc(20);

    printf("[*]Test App: Freeing p1...\n");
    if (p1) free(p1);

    printf("[*]Test App: Freeing p2...\n");
    if (p2) free(p2);
    
    printf("[*[Test App: Allocating and copying with strcpy...\n");
    char buffer[50];
    // This strcpy will also be hooked
    strcpy(buffer, "This is a test string for strcpy.");
    printf("[*]Test App: Buffer content after strcpy: %s\n", buffer);


    printf("[*]Test App: Finished.\n");
    return 0;
}
