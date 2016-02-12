/*
 * Copyright (c) 2013-2014 Jens Kuske <jenskuske@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "ve.h"
#include "kernel-headers/ion.h"
#include "kernel-headers/ion_sunxi.h"

#define DEVICE "/dev/cedar_dev"
#define PAGE_OFFSET (0xc0000000)        // from kernel
#define PAGE_SIZE (4096)

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

enum IOCTL_CMD {
    IOCTL_UNKOWN = 0x100,
    IOCTL_GET_ENV_INFO,
    IOCTL_WAIT_VE,
    IOCTL_RESET_VE,
    IOCTL_ENABLE_VE,
    IOCTL_DISABLE_VE,
    IOCTL_SET_VE_FREQ,

    IOCTL_CONFIG_AVS2 = 0x200,
    IOCTL_GETVALUE_AVS2,
    IOCTL_PAUSE_AVS2,
    IOCTL_START_AVS2,
    IOCTL_RESET_AVS2,
    IOCTL_ADJUST_AVS2,
    IOCTL_ENGINE_REQ,
    IOCTL_ENGINE_REL,
    IOCTL_ENGINE_CHECK_DELAY,
    IOCTL_GET_IC_VER,
    IOCTL_ADJUST_AVS2_ABS,
    IOCTL_FLUSH_CACHE
};

struct ve_info {
    uint32_t reserved_mem;
    int reserved_mem_size;
    uint32_t registers;
};

struct cedarv_cache_range {
    long start;
    long end;
};

struct memchunk_t {
    struct ve_mem mem;
    struct memchunk_t *next;
};

struct ion_mem {
    struct ion_handle *handle;
    int fd;
    struct ve_mem mem;
};

/*
struct ve_t {
    int fd;
    int ion_fd;
    void *regs;
    int version;
    int ioctl_offset;
    struct memchunk_t first_memchunk;
    pthread_rwlock_t memory_lock;
    pthread_mutex_t device_lock;
};
*/

static struct {
    int fd;
    int ion_fd;
    void *regs;
    int version;
    int ioctl_offset;
    struct memchunk_t first_memchunk;
    pthread_rwlock_t memory_lock;
    pthread_mutex_t device_lock;
} ve = {
   .fd = -1,
   .ion_fd = -1,
   .memory_lock = PTHREAD_RWLOCK_INITIALIZER,
   .device_lock = PTHREAD_MUTEX_INITIALIZER
};

int ve_open(void)
{
    if (ve.fd != -1)
        return 0;

    struct ve_info info;

    ve.fd = open(DEVICE, O_RDWR);
    if (ve.fd == -1)
        return 0;

    if (ioctl(ve.fd, IOCTL_GET_ENV_INFO, (void *) (&info)) == -1)
        goto close;

    ve.regs = mmap(NULL, 0x800, PROT_READ | PROT_WRITE, MAP_SHARED, ve.fd, info.registers);
    if (ve.regs == MAP_FAILED)
        goto close;

    ve.first_memchunk.mem.phys = info.reserved_mem - PAGE_OFFSET;
    ve.first_memchunk.mem.size = info.reserved_mem_size;

    if (ve.first_memchunk.mem.size == 0) {
        ve.ion_fd = open("/dev/ion", O_RDONLY);
        if (ve.ion_fd == -1)
            goto unmap;
    }

    ioctl(ve.fd, IOCTL_ENGINE_REQ, 0);

    ve.version = readl(ve.regs + VE_VERSION) >> 16;

    if (ve.version >= 0x1667)
        ve.ioctl_offset = 1;

    ioctl(ve.fd, IOCTL_ENABLE_VE + ve.ioctl_offset, 0);
    ioctl(ve.fd, IOCTL_SET_VE_FREQ + ve.ioctl_offset, 320);
    ioctl(ve.fd, IOCTL_RESET_VE + ve.ioctl_offset, 0);

    writel(0x00130007, ve.regs + VE_CTRL);

    printf("[VDPAU SUNXI] VE version 0x%04x opened.\n", ve.version);

    return 1;

  unmap:
    munmap(ve.regs, 0x800);
  close:
    close(ve.fd);
    ve.fd = -1;
    return 0;
}

void ve_close(void)
{
    if (ve.fd == -1)
        return;

    ioctl(ve.fd, IOCTL_DISABLE_VE + ve.ioctl_offset, 0);
    ioctl(ve.fd, IOCTL_ENGINE_REL, 0);

    munmap(ve.regs, 0x800);
    ve.regs = NULL;

    if (ve.ion_fd != -1)
        close(ve.ion_fd);

    close(ve.fd);
    ve.fd = -1;
}

int ve_get_version(void)
{
    return ve.version;
}

int ve_wait(int timeout)
{
    if (ve.fd == -1)
        return 0;

    return ioctl(ve.fd, IOCTL_WAIT_VE, timeout);
}

void *ve_get(int engine, uint32_t flags)
{
    if (pthread_mutex_lock(&ve.device_lock))
        return NULL;

    writel(0x00130000 | (engine & 0xf) | (flags & ~0xf), ve.regs + VE_CTRL);

    return ve.regs;
}

void ve_put(void)
{
    writel(0x00130007, ve.regs + VE_CTRL);
    pthread_mutex_unlock(&ve.device_lock);
}

static struct ve_mem *ion_malloc(int size)
{
    struct ion_mem *imem = calloc(1, sizeof(struct ion_mem));
    if (!imem) {
        perror("calloc ion_buffer failed");
        return NULL;
    }

    struct ion_allocation_data alloc = {
        .len = size,
        .align = 4096,
        .heap_id_mask = ION_HEAP_TYPE_DMA,
        .flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC,
    };

    if (ioctl(ve.ion_fd, ION_IOC_ALLOC, &alloc)) {
        perror("ION_IOC_ALLOC failed");
        free(imem);
        return NULL;
    }

    imem->handle = alloc.handle;
    imem->mem.size = size;

    struct ion_fd_data map = {
        .handle = imem->handle,
    };

    if (ioctl(ve.ion_fd, ION_IOC_MAP, &map)) {
        perror("ION_IOC_MAP failed");
        free(imem);
        return NULL;
    }

    imem->fd = map.fd;

    imem->mem.virt = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, imem->fd, 0);
    if (imem->mem.virt == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }

    sunxi_phys_data phys = {
        .handle = imem->handle,
    };

    struct ion_custom_data custom = {
        .cmd = ION_IOC_SUNXI_PHYS_ADDR,
        .arg = (unsigned long) (&phys),
    };

    if (ioctl(ve.ion_fd, ION_IOC_CUSTOM, &custom)) {
        perror("ION_IOC_CUSTOM(SUNXI_PHYS_ADDR) failed");
        free(imem);
        return NULL;
    }

    imem->mem.phys = phys.phys_addr - 0x40000000;

    return &imem->mem;
}

struct ve_mem *ve_malloc(int size)
{
    if (ve.fd == -1)
        return NULL;

    if (ve.ion_fd != -1)
        return ion_malloc(size);

    if (pthread_rwlock_wrlock(&ve.memory_lock))
        return NULL;

    void *addr = NULL;
    struct ve_mem *ret = NULL;

    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    struct memchunk_t *c, *best_chunk = NULL;
    for (c = &ve.first_memchunk; c != NULL; c = c->next) {
        if (c->mem.virt == NULL && c->mem.size >= size) {
            if (best_chunk == NULL || c->mem.size < best_chunk->mem.size)
                best_chunk = c;

            if (c->mem.size == size)
                break;
        }
    }

    if (!best_chunk)
        goto out;

    int left_size = best_chunk->mem.size - size;

    addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, ve.fd, best_chunk->mem.phys + PAGE_OFFSET);
    if (addr == MAP_FAILED) {
        ret = NULL;
        goto out;
    }

    best_chunk->mem.virt = addr;
    best_chunk->mem.size = size;

    if (left_size > 0) {
        c = malloc(sizeof(struct memchunk_t));
        c->mem.phys = best_chunk->mem.phys + size;
        c->mem.size = left_size;
        c->mem.virt = NULL;
        c->next = best_chunk->next;
        best_chunk->next = c;
    }

    ret = &best_chunk->mem;
  out:
    pthread_rwlock_unlock(&ve.memory_lock);
    return ret;
}

static void ion_free(struct ve_mem *mem)
{
    if (ve.ion_fd == -1 || !mem)
        return;

    struct ion_mem *imem = container_of(mem, struct ion_mem, mem);

    if (munmap(mem->virt, mem->size)) {
        perror("munmap failed");
        return;
    }

    close(imem->fd);

    struct ion_handle_data handle = {
        .handle = imem->handle,
    };

    if (ioctl(ve.ion_fd, ION_IOC_FREE, &handle)) {
        perror("ION_IOC_FREE failed");
        free(imem);
        return;
    }
}

void ve_free(struct ve_mem *mem)
{
    if (ve.fd == -1)
        return;

    if (mem == NULL)
        return;

    if (ve.ion_fd != -1)
        ion_free(mem);

    if (pthread_rwlock_wrlock(&ve.memory_lock))
        return;

    struct memchunk_t *c;
    for (c = &ve.first_memchunk; c != NULL; c = c->next) {
        if (&c->mem == mem) {
            munmap(c->mem.virt, c->mem.size);
            c->mem.virt = NULL;
            break;
        }
    }

    for (c = &ve.first_memchunk; c != NULL; c = c->next) {
        if (c->mem.virt == NULL) {
            while (c->next != NULL && c->next->mem.virt == NULL) {
                struct memchunk_t *n = c->next;
                c->mem.size += n->mem.size;
                c->next = n->next;
                free(n);
            }
        }
    }

    pthread_rwlock_unlock(&ve.memory_lock);
}

void ve_flush_cache(struct ve_mem *mem)
{
    if (ve.fd == -1)
        return;

    if (ve.ion_fd != -1) {
        sunxi_cache_range range = {
            .start = (long) mem->virt,
            .end = (long) mem->virt + mem->size,
        };

        struct ion_custom_data cache = {
            .cmd = ION_IOC_SUNXI_FLUSH_RANGE,
            .arg = (unsigned long) (&range),
        };

        if (ioctl(ve.ion_fd, ION_IOC_CUSTOM, &cache))
            perror("ION_IOC_CUSTOM(SUNXI_FLUSH_RANGE) failed");
    } else {
        struct cedarv_cache_range range = {
            .start = (int) mem->virt,
            .end = (int) mem->virt + mem->size
        };

        ioctl(ve.fd, IOCTL_FLUSH_CACHE, (void *) (&range));
    }
}


uint32_t ve_virt2phys(struct ve_mem *mem)
{
    if (ve.fd == -1)
        return 0;
        
    if (ve.ion_fd != -1) {
        if (!mem)
            return 0;
        return mem->phys;    
    } 
    /* to do */
    return 0;
}

void veisp_set_buffers(struct ve_mem * Y_mem, struct ve_mem * C_mem)
{
    uint32_t pY = ve_virt2phys(Y_mem);
    uint32_t pC = ve_virt2phys(C_mem);
    // S(pY, ve, VE_ISP_PIC_LUMA);
    writel(pY, ve.regs + VE_ISP_PIC_LUMA);
    // S(pC, ve, VE_ISP_PIC_CHROMA);
    writel(pC, ve.regs + VE_ISP_PIC_CHROMA);
}

inline void veisp_set_picture_size(uint32_t w, uint32_t h)
{
    uint32_t width_mb = (w + 15) / 16;
    uint32_t height_mb = (h + 15) / 16;
    uint32_t size = ((width_mb & 0x3ff) << 16) | (height_mb & 0x3ff);
    uint32_t stride = (width_mb & 0x3ff) << 16;

    // S(size, ve, VE_ISP_PIC_SIZE);
    writel(size, ve.regs + VE_ISP_PIC_SIZE);
    // S(stride, ve, VE_ISP_PIC_STRIDE);
    writel(stride, ve.regs + VE_ISP_PIC_STRIDE);
}

void veisp_init_picture(uint32_t w, uint32_t h, veisp_color_format f)
{
    uint32_t format = (f & 0xf) << 28;
    veisp_set_picture_size(w, h);

    // S(format, ve, VE_ISP_CTRL);
    writel(format, ve.regs + VE_ISP_CTRL);
}

static veavc_encoder_mode encoder_mode = VEAVC_ENCODER_MODE_H264;

void veavc_select_subengine(void)
{
    uint32_t ctrl; //  = L(ve,VE_CTRL);
    
    ctrl = readl(ve.regs + VE_CTRL) & 0xf;
    ctrl = (ctrl & 0xfffffff0) | 0xb;
    // S(ctrl, ve, VE_CTRL);
    writel(ctrl, ve.regs + VE_CTRL);
}

void veavc_init_vle(struct ve_mem * J_mem, uint32_t size)
{
    uint32_t pJ = ve_virt2phys(J_mem);
    uint32_t end = pJ + size - 1;
    uint32_t maxbits = (size * 8 + 0xffff) & ~0xffff;
    uint32_t max = maxbits > 0x0fff0000 ? 0x0fff0000 : maxbits;
    // S(pJ, ve, VE_AVC_VLE_ADDR);
    writel(pJ, ve.regs + VE_AVC_VLE_ADDR);
    // S(end, ve, VE_AVC_VLE_END);
    writel(end, ve.regs + VE_AVC_VLE_END);
    // S(0, ve, VE_AVC_VLE_OFFSET);
    writel(0, ve.regs + VE_AVC_VLE_OFFSET);
    // S(max, ve, VE_AVC_VLE_MAX);
    writel(max, ve.regs + VE_AVC_VLE_MAX);
    printf("[VEAVC] outbuf of size %d, write only max %d bytes\n", size, max / 8);
}

void veavc_init_ctrl(veavc_encoder_mode mode)
{
    uint32_t trigger = (mode & 1) << 16;
    uint32_t status;
    encoder_mode = mode;

    // S(0x0000000f, ve, VE_AVC_CTRL);
    writel(0x0000000f, ve.regs + VE_AVC_CTRL);
    // S(trigger, ve, VE_AVC_TRIGGER);
    writel(trigger, ve.regs + VE_AVC_TRIGGER);

    /* clear status bits */
    // status = L(VE_AVC_STATUS);
    status = readl(ve.regs + VE_AVC_STATUS);
    
    // S(status | 0xf, ve, VE_AVC_STATUS);
    writel(status | 0xf, ve.regs + VE_AVC_STATUS);
}

void veavc_jpeg_parameters(uint8_t fill1, uint8_t stuff, uint32_t biasY, uint32_t biasC)
{
    uint32_t valfill1 = fill1 > 0 ? 1 : 0;
    uint32_t valstuff = stuff > 0 ? 1 : 0;
    uint32_t value = 0;
    value |= (valfill1 & 1) << 31;
    value |= (valstuff & 1) << 30;
    value |= (biasC & 0x7ff) << 16;
    value |= (biasY & 0x7ff) << 0;
    // S(value, ve, VE_AVC_PARAM);
    writel(value, ve.regs + VE_AVC_PARAM);
}

static const char *status_to_print(uint32_t status)
{
    uint32_t value = status & 0xf;
    if (value == 0)
        return "none";
    if (value == 1)
        return "success";
    if (value == 2)
        return "failed";
    return "unknown";
}

void veavc_put_bits(uint8_t nbits, uint32_t data)
{
    uint32_t trigger = (encoder_mode & 1) << 16;
    uint32_t status;
    trigger |= (nbits & 0x3f) << 8;
    trigger |= 1;
    // S(data, ve, VE_AVC_BASIC_BITS);
    writel(data, ve.regs + VE_AVC_BASIC_BITS);
    // S(trigger, ve, VE_AVC_TRIGGER);
    writel(trigger, ve.regs + VE_AVC_TRIGGER);

    // status = L(ve,VE_AVC_STATUS) & 0xf;
    status = readl(ve.regs + VE_AVC_STATUS) & 0xf;
    // if (status)
        printf("[VEAVC] put bits status %d (%s)\n", status, status_to_print(status));
}

void veavc_sdram_index(uint32_t index)
{
    // S(index, ve, VE_AVC_SDRAM_INDEX);
    writel(index, ve.regs + VE_AVC_SDRAM_INDEX);
}

void veavc_jpeg_quantization(uint16_t * tableY, uint16_t * tableC, uint32_t length)
{
    uint32_t data;
    int i;

    veavc_sdram_index(0x0);

/*
	When compared to libjpeg, there are still rounding errors in the
	coefficients values (around 1 unit of difference).
*/
    for (i = 0; i < length; i++) {
        data = 0x0000ffff & (0xffff / tableY[i]);
        data |= 0x00ff0000 & (((tableY[i] + 1) / 2) << 16);
        // S(data, ve, VE_AVC_SDRAM_DATA);
        writel(data, ve.regs + VE_AVC_SDRAM_DATA);
    }
    for (i = 0; i < length; i++) {
        data = 0x0000ffff & (0xffff / tableC[i]);
        data |= 0x00ff0000 & (((tableC[i] + 1) / 2) << 16);
        // S(data, ve, VE_AVC_SDRAM_DATA);
        writel(data, ve.regs + VE_AVC_SDRAM_DATA);
    }
}

void veavc_launch_encoding(void)
{
    uint32_t trigger = (encoder_mode & 1) << 16;
    trigger |= 8;
    // S(trigger, ve, VE_AVC_TRIGGER);
    writel(trigger, ve.regs + VE_AVC_TRIGGER);
}

void veavc_check_status(void)
{
    uint32_t status; //  = L(ve, VE_AVC_STATUS) & 0xf;
    
    status = readl(ve.regs + VE_AVC_STATUS) & 0xf;
    //if (status)
        printf("[VEAVC] finish status %d (%s)\n", status, status_to_print(status));
}

uint32_t veavc_get_written(void)
{
    uint32_t bits; //  = L(ve, VE_AVC_VLE_LENGTH);
    bits = readl(ve.regs + VE_AVC_VLE_LENGTH) & 0xf;
    return bits / 8;
}

