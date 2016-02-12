/*
 * Copyright (c) 2014 Manuel Braga <mul.braga@gmail.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ve.h"
#include "vepoc.h"


int main(int argc, char *argv[])
{
    int rc;
    char *outjpeg = "poc.jpeg";
    int quality = 100;
    uint32_t w = 0;
    uint32_t h = 0;
    uint32_t bufsize = 0;
    struct ve_mem *Y_mem = NULL;
    struct ve_mem *C_mem = NULL;
    struct ve_mem *J_mem = NULL;
    uint8_t *Y = NULL;
    uint8_t *C = NULL;
    uint8_t *J = NULL;
    uint32_t Jsize = 0;
    uint32_t Jwritten = 0;

    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s width height quality [out.jpeg]\n", argv[0]);
        return 1;
    }

    w = atoi(argv[1]);
    h = atoi(argv[2]);
    quality = atoi(argv[3]);
    if (argc > 4)
        outjpeg = argv[4];

    rc = ve_open();
    if (rc == 0) {
        printf("[JEPOC] error: could not open ve engine!\n");
        return 1;
    }

    w = (w + 15) & ~15;
    h = (h + 15) & ~15;
    printf("[JEPOC] picture %dx%-d at %d quality\n", w, h, quality);
    /* 3 times to leave enough room to try different color formats */
    bufsize = w * h;
    Y_mem = ve_malloc(bufsize);
    if (!Y_mem) {
        printf("[JEPOC] ve memory error! [%d]\n", __LINE__);
        return 1;
    }
    Y = (uint8_t *) Y_mem->virt;
    C_mem = ve_malloc(bufsize);
    if (!C_mem) {
        printf("[JEPOC] ve memory error! [%d]\n", __LINE__);
        return 1;
    }
    C = (uint8_t *) C_mem->virt;
    memset(Y, 0x80, bufsize);
    memset(C, 0x80, bufsize);
    picture_generate(w, h, Y, C);
    printf("[JEPOC] picture generated.\n");

    /* flush for H3 */
    ve_flush_cache(Y_mem);
    ve_flush_cache(C_mem);

    Jsize = 0x800000;
    J_mem = ve_malloc(Jsize);
    if (!J_mem) {
        printf("[JEPOC] ve memory error! [%d]\n", __LINE__);
        return 1;
    }
    J = (uint8_t *) J_mem->virt;

    veavc_select_subengine();
    veisp_set_buffers(Y_mem, C_mem);
    veisp_init_picture(w, h, VEISP_COLOR_FORMAT_NV12);

    veavc_init_vle(J_mem, Jsize);
    veavc_init_ctrl(VEAVC_ENCODER_MODE_JPEG);
    veavc_jpeg_parameters(1, 0, 0, 0);

    vejpeg_header_create(w, h, quality);
    vejpeg_write_SOF0();
    vejpeg_write_SOS();
    vejpeg_write_quantization();

    printf("[JEPOC] launch encoding.\n");
    veavc_launch_encoding();
    ve_wait(2);
    veavc_check_status();

    Jwritten = veavc_get_written();
    /* flush for H3 */
    ve_flush_cache(J_mem);
    vejpeg_write_file(outjpeg, J, Jwritten);
    printf("[JEPOC] written %d bytes to %s\n", Jwritten, outjpeg);

    ve_free(J_mem);
    ve_free(C_mem);
    ve_free(Y_mem);
    ve_close();
    return 0;
}
