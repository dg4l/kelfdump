#include <kernel.h>
#include <delaythread.h>
#include <sifrpc.h>
#include <loadfile.h>
#include <iopcontrol.h>
#include <sbv_patches.h>
#define NEWLIB_PORT_AWARE
#include <fileXio_rpc.h>
#include <debug.h>
#include <libpad.h>
#include <dirent.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common.h"
#include "erom.h"

#define OUT_DIR "mass:/KELFDUMP"

#define IRX(name) \
    extern unsigned char name##_irx[]; \
    extern unsigned int size_##name##_irx;

IRX(sio2man)
IRX(padman)
IRX(iomanX)
IRX(fileXio)
IRX(usbd)
IRX(bdm)
IRX(bdmfs_fatfs)
IRX(usbmass_bd)
IRX(kelfdump)

static KdRpc rpc __attribute__((aligned(64)));
static SifRpcClientData_t client;
static char pad_buf[256] __attribute__((aligned(64)));
static bool pad_ready;
static int log_fd = -1;
static int decrypted;
static int failed;

static void log_msg(const char* fmt, ...) {
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    scr_printf("%s", line);
    if (log_fd >= 0) write(log_fd, line, strlen(line));
}

static void pad_init(void) {
    if (padInit(0) != 1) return;
    pad_ready = padPortOpen(0, 0, pad_buf) != 0;
}

static void halt(void) {
    if (log_fd >= 0) close(log_fd);
    log_fd = -1;
    if (!pad_ready) SleepThread();
    scr_printf("\nPress X to exit.\n");
    struct padButtonStatus pad;
    for (;;) {
        int state = padGetState(0, 0);
        if ((state == PAD_STATE_STABLE || state == PAD_STATE_FINDCTP1) && padRead(0, 0, &pad)) {
            if (!(pad.btns & PAD_CROSS)) break;
        }
        DelayThread(16 * 1000);
    }
    padPortClose(0, 0);
    padEnd();
    Exit(0);
}

static bool load_irx(const char* name, void* buf, unsigned int size) {
    int ret;
    int id = SifExecModuleBuffer(buf, size, 0, NULL, &ret);
    if (id < 0 || ret == 1) {
        scr_printf("Failed to load %s (%d, %d)\n", name, id, ret);
        return false;
    }
    return true;
}

static bool call(int fn, uint32_t in, uint32_t out) {
    return sceSifCallRpc(&client, fn, 0, &rpc, KD_HDR_SIZE + in, &rpc, KD_HDR_SIZE + out, NULL, NULL) >= 0;
}

static uint8_t* read_iop(uint32_t addr, uint32_t size) {
    uint8_t* buf = memalign(64, size);
    if (!buf) return NULL;
    for (uint32_t done = 0; done < size; done += KD_MAX) {
        uint32_t n = size - done < KD_MAX ? size - done : KD_MAX;
        rpc.addr = addr + done;
        rpc.size = n;
        if (!call(KD_READ, 0, n)) {
            log_msg("  RPC read failed at %08X\n", rpc.addr);
            free(buf);
            return NULL;
        }
        memcpy(buf + done, rpc.data, n);
    }
    return buf;
}

static void write_file(const char* dir, const char* name, const void* buf, uint32_t size) {
    char path[256];
    snprintf(path, sizeof(path), OUT_DIR "/%s", dir);
    mkdir(path, 0777);
    snprintf(path, sizeof(path), OUT_DIR "/%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        log_msg("  cannot create %s (%d)\n", path, fd);
        return;
    }
    if (write(fd, buf, size) != (int)size) log_msg("  short write on %s\n", path);
    close(fd);
}

static bool is_kelf(const uint8_t* p, uint32_t size) {
    const SecrKELFHeader_t* h = (const SecrKELFHeader_t*)p;
    return size > sizeof(*h) && h->KELF_header_size >= sizeof(*h) && h->KELF_header_size + h->ELF_size == size;
}

// send KELF to IOP over RPC one block at a time for decryption
static uint8_t* decrypt_kelf(const uint8_t* kelf, uint32_t size) {
    const SecrKELFHeader_t* h = (const SecrKELFHeader_t*)kelf;
    if (h->KELF_header_size > KD_MAX) return NULL;
    memcpy(rpc.data, kelf, h->KELF_header_size);
    if (!call(KD_HEADER, h->KELF_header_size, 0) || !rpc.result) {
        log_msg("  MechaCon rejected the header\n");
        return NULL;
    }
    SecrBitTable_t bit = rpc.bit;
    if (bit.header.block_count > sizeof(bit.blocks) / sizeof(bit.blocks[0])) {
        log_msg("  too many blocks (%u)\n", bit.header.block_count);
        return NULL;
    }
    uint8_t* out = malloc(size);
    if (!out) return NULL;
    memcpy(out, kelf, size);
    uint32_t offset = bit.header.headersize;
    for (uint32_t i = 0; i < bit.header.block_count; ++i) {
        uint32_t bsize = bit.blocks[i].size;
        if (offset + bsize > size) {
            log_msg("  bad block %u (size %u)\n", i, bsize);
            free(out);
            return NULL;
        }
        if (bit.blocks[i].flags & 3) {
            // only blocks sent to the MechaCon have to fit in the RPC buffer, plain ones don't matter
            if (bsize > KD_MAX) {
                log_msg("  block %u too big to send (size %u, flags %u)\n", i, bsize, bit.blocks[i].flags);
                free(out);
                return NULL;
            }
            memcpy(rpc.data, out + offset, bsize);
            rpc.size = bsize;
            if (!call(KD_BLOCK, bsize, bsize) || !rpc.result) {
                log_msg("  MechaCon failed on block %u\n", i);
                free(out);
                return NULL;
            }
            memcpy(out + offset, rpc.data, bsize);
        }
        offset += bsize;
    }
    return out;
}

static void handle_file(const char* dir, const char* name, const uint8_t* data, uint32_t size) {
    if (!is_kelf(data, size)) return;
    const SecrKELFHeader_t* h = (const SecrKELFHeader_t*)data;
    char out_name[32];
    log_msg("%s/%s: KELF, %u bytes\n", dir, name, size);
    snprintf(out_name, sizeof(out_name), "%s.kelf", name);
    write_file(dir, out_name, data, size);
    uint8_t* dec = decrypt_kelf(data, size);
    if (!dec) {
        ++failed;
        return;
    }
    uint8_t* payload = dec + h->KELF_header_size;
    snprintf(out_name, sizeof(out_name), "%s.dec", name);
    write_file(dir, out_name, payload, h->ELF_size);
    log_msg("  decrypted %u bytes%s\n", h->ELF_size, memcmp(payload, "\x7f" "ELF", 4) ? "" : " (ELF)");
    ++decrypted;
    free(dec);
}

// table is right after RESET
static const uint8_t* find_romdir(const uint8_t* start, uint32_t avail) {
    uint32_t limit = avail < 0x40000 ? avail : 0x40000;
    for (uint32_t i = 0; i + 32 <= limit; i += 16) {
        const uint8_t* p = start + i;
        uint32_t size = *(const uint32_t*)(p + 12);
        if (!memcmp(p, "RESET", 6) && !memcmp(p + 16, "ROMDIR", 7) && ((size + 15) & ~15) == i) return p;
    }
    return NULL;
}

static void scan_romfs(const char* dir, const uint8_t* start, const uint8_t* table, uint32_t avail) {
    uint32_t offset = 0;
    for (const uint8_t* entry = table; entry + 16 <= start + avail && entry[0]; entry += 16) {
        char name[11] = {0};
        uint32_t size = *(const uint32_t*)(entry + 12);
        if (offset + size > avail) break;
        memcpy(name, entry, 10);
        handle_file(dir, name, start + offset, size);
        offset += (size + 15) & ~15;
    }
}

static uint32_t scan_erom(const uint8_t* start, uint32_t avail) {
    const EromFd* first = erom_find(start);
    if (!first) return 0;
    uint32_t total = erom_size(first);
    if (total > avail) return 0;
    log_msg("erom found, %u bytes\n", total);
    for (const EromFd* fd = erom_next(start, first); fd; fd = erom_next(start, fd)) {
        if ((const uint8_t*)fd < start || (const uint8_t*)fd >= start + total) break;
        uint32_t size = erom_file_size(fd);
        if (size > total) break;
        uint8_t* buf = malloc(size);
        if (!buf) break;
        char name[16];
        erom_read(start, fd, buf);
        erom_file_name(fd, name);
        if (size > 2 && buf[0] == 0x1F && buf[1] == 0x8B) strcat(name, ".gz");
        write_file("erom", name, buf, size);
        handle_file("erom", name, buf, size);
        free(buf);
    }
    return total;
}

int main(void) {
    SifInitRpc(0);
    while (!SifIopReset("", 0));
    while (!SifIopSync());
    SifInitRpc(0);
    sbv_patch_enable_lmb();
    sbv_patch_disable_prefix_check();
    init_scr();
    scr_printf("kelfdump\n\n");
    SifLoadModule("rom0:ADDDRV", 0, NULL);
    if (load_irx("sio2man", sio2man_irx, size_sio2man_irx) &&
        load_irx("padman", padman_irx, size_padman_irx)) {
        pad_init();
    }
    if (!load_irx("iomanX", iomanX_irx, size_iomanX_irx) ||
        !load_irx("fileXio", fileXio_irx, size_fileXio_irx) ||
        !load_irx("usbd", usbd_irx, size_usbd_irx) ||
        !load_irx("bdm", bdm_irx, size_bdm_irx) ||
        !load_irx("bdmfs_fatfs", bdmfs_fatfs_irx, size_bdmfs_fatfs_irx) ||
        !load_irx("usbmass_bd", usbmass_bd_irx, size_usbmass_bd_irx) ||
        !load_irx("kelfdump", kelfdump_irx, size_kelfdump_irx)) {
        halt();
    }
    fileXioInit();
    scr_printf("Waiting for USB drive...\n");
    bool usb_ready = false;
    for (int i = 0; i < 100 && !usb_ready; ++i) {
        DIR* d = opendir("mass:/");
        if (d) {
            closedir(d);
            usb_ready = true;
        }
        else {
            DelayThread(100 * 1000);
        }
    }
    if (!usb_ready) {
        scr_printf("No USB drive found.\n");
        halt();
    }
    mkdir(OUT_DIR, 0777);
    log_fd = open(OUT_DIR "/log.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    while (sceSifBindRpc(&client, KD_RPC_ID, 0) < 0 || !client.server) DelayThread(10 * 1000);
    call(KD_INFO, 0, 0);
    KdInfo info = rpc.info;
    log_msg("rom0 %08X (%u bytes), DEV1 %08X (%u bytes)\n", info.rom0_addr, info.rom0_size, info.dev1_addr, info.dev1_size);
    uint8_t* rom0 = read_iop(info.rom0_addr, info.rom0_size);
    uint8_t* dev1 = read_iop(info.dev1_addr, info.dev1_size);
    if (!rom0 || !dev1) {
        log_msg("Failed to read ROM regions from IOP\n");
        halt();
    }
    write_file("raw", "rom0.bin", rom0, info.rom0_size);
    write_file("raw", "dev1.bin", dev1, info.dev1_size);
    const uint8_t* table = find_romdir(rom0, info.rom0_size);
    if (table) scan_romfs("rom0", rom0, table, info.rom0_size);
    int roms = 0;
    for (uint32_t off = 0; off < info.dev1_size; off += 0x10000) {
        const uint8_t* block = dev1 + off;
        uint32_t avail = info.dev1_size - off;
        table = find_romdir(block, avail);
        if (table) {
            if (off > 0 && !memcmp(block, dev1, 0x100)) break;
            char dir[16];
            sprintf(dir, "rom%d", ++roms);
            scan_romfs(dir, block, table, avail);
        }
        else {
            uint32_t size = scan_erom(block, avail);
            if (size) off += ((size + 0xFFFF) & ~0xFFFF) - 0x10000;
        }
    }
    log_msg("\nDone: %d decrypted, %d failed. Files are in " OUT_DIR "\n", decrypted, failed);
    halt();
    return 0;
}
