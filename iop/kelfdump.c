#include "irx_imports.h"
#include "../common.h"

IRX_ID("kelfdump", 1, 0);

static SifRpcDataQueue_t queue;
static SifRpcServerData_t server;
static KdRpc rpc_buf;

static uint32_t size_from_delay(int dev) {
    return 1 << ((GetDelay(dev) >> 16) & 0x1F);
}

static void* handler(int fn, void* data, int size) {
    (void)size;
    KdRpc* p = data;
    switch (fn) {
        case KD_INFO:
            p->info.rom0_addr = 0xBFC00000;
            p->info.rom0_size = size_from_delay(SSBUSC_DEV_BOOTROM);
            p->info.dev1_addr = GetBaseAddress(SSBUSC_DEV_DVDROM) | 0xA0000000;
            p->info.dev1_size = size_from_delay(SSBUSC_DEV_DVDROM);
            break;
        case KD_READ:
            memcpy(p->data, (void*)p->addr, p->size);
            break;
        case KD_HEADER:
            p->result = SecrDiskBootHeader(p->data, &p->bit, NULL);
            break;
        case KD_BLOCK:
            p->result = SecrDiskBootBlock(p->data, p->data, p->size);
            break;
    }
    return data;
}

static void rpc_thread(void* arg) {
    (void)arg;
    if (!sceSifCheckInit()) sceSifInit();
    sceSifInitRpc(0);
    sceSifSetRpcQueue(&queue, GetThreadId());
    sceSifRegisterRpc(&server, KD_RPC_ID, &handler, &rpc_buf, NULL, NULL, &queue);
    sceSifRpcLoop(&queue);
}

int _start(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    iop_thread_t thread = {
        .attr = TH_C,
        .thread = &rpc_thread,
        .stacksize = 0x800,
        .priority = 0x28,
    };
    int id = CreateThread(&thread);
    if (id <= 0) return MODULE_NO_RESIDENT_END;
    StartThread(id, NULL);
    return MODULE_RESIDENT_END;
}
