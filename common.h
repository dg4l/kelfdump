#pragma once
#include <stdint.h>
#include <tamtypes.h>
#include <libsecr-common.h>

#define KD_RPC_ID 0x4B444D50
#define KD_MAX    0x10000

enum {
    KD_INFO,
    KD_READ,
    KD_HEADER,
    KD_BLOCK,
};

typedef struct {
    uint32_t rom0_addr;
    uint32_t rom0_size;
    uint32_t dev1_addr;
    uint32_t dev1_size;
}KdInfo;

typedef struct {
    uint32_t addr;
    uint32_t size;
    int32_t result;
    KdInfo info;
    SecrBitTable_t bit;
    uint8_t data[KD_MAX] __attribute__((aligned(64)));
}KdRpc;

#define KD_HDR_SIZE ((uint32_t)(uintptr_t)&((KdRpc*)0)->data)
