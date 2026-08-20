#include <stdint.h>
#include <string.h>

int parse_shared(const unsigned char *data, int len) {
    char record[8];

    if (len < 5 || memcmp(data, "ZVSL!", 5) != 0) {
        return 0;
    }
    memcpy(record, data + 5, (size_t)(len - 5));
    return record[0];
}
