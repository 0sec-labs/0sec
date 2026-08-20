#include <stdio.h>

__attribute__((noinline))
static int parse(const char *path) {
    return path[0] == '\0';
}

int main(int argc, char **argv) {
    int first;
    FILE *input;

    if (argc != 2) {
        return 2;
    }
    input = fopen(argv[1], "rb");
    if (input == NULL) {
        return 3;
    }
    first = fgetc(input);
    fclose(input);
    return first == 'R' ? parse(argv[1]) : 0;
}
