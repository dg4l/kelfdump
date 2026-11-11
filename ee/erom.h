#pragma once
#include <stdint.h>

typedef struct {
    uint32_t name_hash;
    uint32_t offset_hash;
    uint32_t size_hash;
    uint32_t next_hash;
    uint32_t xorsize_hash;
} EromFd;

const EromFd* erom_find(const uint8_t* start);
const EromFd* erom_next(const uint8_t* start, const EromFd* fd);
uint32_t erom_size(const EromFd* first);
uint32_t erom_file_size(const EromFd* fd);
void erom_read(const uint8_t* start, const EromFd* fd, uint8_t* out);
void erom_file_name(const EromFd* fd, char* name);
