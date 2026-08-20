#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t read_be32(const unsigned char *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[2] << 8) | data[3];
}

static uint32_t crc32_byte(uint32_t crc, unsigned char value) {
    crc ^= value;
    for (unsigned int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320U : crc >> 1;
    }
    return crc;
}

static uint32_t chunk_crc(const unsigned char *type, const unsigned char *data, size_t size) {
    uint32_t crc = 0xffffffffU;
    for (size_t index = 0; index < 4; ++index) {
        crc = crc32_byte(crc, type[index]);
    }
    for (size_t index = 0; index < size; ++index) {
        crc = crc32_byte(crc, data[index]);
    }
    return crc ^ 0xffffffffU;
}

__attribute__((noinline)) static int png_sink(const unsigned char *data, size_t size) {
    volatile unsigned char observed = data[size - 1];
    return observed;
}

static int valid_ihdr(const unsigned char *data, size_t size) {
    if (size != 13 || read_be32(data) == 0 || read_be32(data + 4) == 0) {
        return 0;
    }
    if (data[10] != 0 || data[11] != 0 || data[12] > 1) {
        return 0;
    }
    switch (data[9]) {
    case 0:
        return data[8] == 1 || data[8] == 2 || data[8] == 4 || data[8] == 8 || data[8] == 16;
    case 2:
    case 4:
    case 6:
        return data[8] == 8 || data[8] == 16;
    case 3:
        return data[8] == 1 || data[8] == 2 || data[8] == 4 || data[8] == 8;
    default:
        return 0;
    }
}

static int parse_png(const unsigned char *data, size_t size) {
    static const unsigned char signature[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    size_t offset = 8;
    int saw_ihdr = 0;
    int saw_idat = 0;

    if (size < sizeof(signature) || memcmp(data, signature, sizeof(signature)) != 0) {
        return 0;
    }
    while (offset < size) {
        if (size - offset < 12) {
            return 0;
        }
        uint32_t length = read_be32(data + offset);
        const unsigned char *type = data + offset + 4;
        const unsigned char *payload = type + 4;
        if ((size_t)length > size - offset - 12) {
            return 0;
        }
        const unsigned char *stored_crc = payload + length;
        if (chunk_crc(type, payload, length) != read_be32(stored_crc)) {
            return 0;
        }
        if (memcmp(type, "IHDR", 4) == 0) {
            if (saw_ihdr || !valid_ihdr(payload, length)) {
                return 0;
            }
            saw_ihdr = 1;
        } else if (memcmp(type, "IDAT", 4) == 0) {
            if (!saw_ihdr) {
                return 0;
            }
            saw_idat = 1;
        } else if (memcmp(type, "IEND", 4) == 0) {
            if (length != 0 || !saw_ihdr || !saw_idat || payload + 4 != data + size) {
                return 0;
            }
            return png_sink(data, size) >= 0;
        }
        offset += (size_t)length + 12;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) {
        return 2;
    }
    if (fseek(input, 0, SEEK_END) != 0) {
        fclose(input);
        return 2;
    }
    long length = ftell(input);
    if (length <= 0 || fseek(input, 0, SEEK_SET) != 0) {
        fclose(input);
        return 2;
    }
    unsigned char *data = malloc((size_t)length);
    if (data == NULL || fread(data, 1, (size_t)length, input) != (size_t)length) {
        free(data);
        fclose(input);
        return 2;
    }
    fclose(input);
    int result = parse_png(data, (size_t)length);
    free(data);
    return result ? 0 : 1;
}
