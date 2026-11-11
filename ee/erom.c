// based on eromdir (WTFPL)

#include <stdio.h>
#include <string.h>
#include "erom.h"

static const char* tokens[] = {
    " A B C", " B C D", " C D E", " D E F", " E F G", " F G H", " G H I", " H I J",
    " I J K", " J K L", " K L M", " L M N", " M N O", " N O P", " O P Q", " P Q R",
    " Q R S", " R S T", " S T U", " T U V", " U V W", " V W X", " W X Y", " X Y Z",
    NULL
};

static uint32_t hash0(uint32_t hash) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i += 4) {
        uint32_t r = hash % 18;
        uint32_t v = r - 1;
        if (v >= 10) v = r - 2;
        ret |= v << i;
        hash /= 18;
    }
    return ret;
}

static uint32_t hash1(uint32_t hash) {
    uint32_t ret = 0;
    for (int i = 0; i < 32; i += 4) {
        uint32_t r = hash % 19;
        uint32_t v = r + 9;
        if (r - 1 >= 6) v = r - 8;
        ret |= v << i;
        hash /= 19;
    }
    return ret;
}

static uint32_t hash_char(uint32_t c) {
    if (c - 'A' < 13) return c - '@';
    if (c == 0) return 14;
    if (c >= 'N') return c - '?';
    if (c == ' ') return 28;
    return c - 0x13;
}

static char dehash_char(uint32_t v) {
    if (v >= 1 && v <= 13) return 'A' + v - 1;
    if (v >= 15 && v <= 27) return 'N' + v - 15;
    if (v == 28) return ' ';
    if (v >= 29 && v <= 38) return '0' + v - 29;
    return '\0';
}

static uint32_t hash_name(const char* name) {
    char str[7] = {0};
    uint32_t hash = 0;
    strncpy(str, name, 6);
    for (int i = 0; i < 6; ++i) hash = hash * 40 + hash_char((uint8_t)str[i]);
    return hash;
}

// the first descriptor is named after one of the tokens
const EromFd* erom_find(const uint8_t* start) {
    const uint32_t* p = (const uint32_t*)start;
    for (int t = 0; tokens[t]; ++t) {
        uint32_t h = hash_name(tokens[t]);
        for (int i = 0; i < 256; ++i) {
            if (p[i] == h) return (const EromFd*)&p[i];
        }
    }
    return NULL;
}

const EromFd* erom_next(const uint8_t* start, const EromFd* fd) {
    uint32_t next = hash0(fd->next_hash);
    return next ? (const EromFd*)(start + next) : NULL;
}

uint32_t erom_size(const EromFd* first) {
    return hash0(first->offset_hash);
}

uint32_t erom_file_size(const EromFd* fd) {
    return hash1(fd->size_hash) & 0xFFFFFF;
}

void erom_read(const uint8_t* start, const EromFd* fd, uint8_t* out) {
    uint32_t size = erom_file_size(fd);
    uint32_t xorsize = hash0(fd->xorsize_hash) * 4;
    const uint8_t* data = start + hash0(fd->offset_hash);
    const uint8_t* table = data - xorsize;
    for (uint32_t i = 0; i < size; ++i) {
        out[i] = i < xorsize ? data[i] ^ table[i] : data[i];
    }
}

void erom_file_name(const EromFd* fd, char* name) {
    uint32_t hash = fd->name_hash;
    for (int i = 5; i >= 0; --i) {
        name[i] = dehash_char(hash % 40);
        hash /= 40;
    }
    name[6] = '\0';
    // fallback to hex if fucked
    if (!name[0] || hash_name(name) != fd->name_hash) sprintf(name, "%08X", (unsigned int)fd->name_hash);
}
