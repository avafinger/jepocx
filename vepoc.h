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

#ifndef _VEPOC_H_
#define _VEPOC_H_


void picture_generate(uint32_t w, uint32_t h, uint8_t *Y, uint8_t *C);

void vejpeg_header_create(int w, int h, int quality);
void vejpeg_header_destroy(void);
void vejpeg_write_SOF0(void);
void vejpeg_write_SOS(void);
void vejpeg_write_quantization(void);
void vejpeg_write_file(const char *filename, uint8_t *buffer, uint32_t length);

void veisp_set_buffers(struct ve_mem * Y_mem, struct ve_mem * C_mem);
void veisp_set_picture_size(uint32_t w, uint32_t h);
void veisp_init_picture(uint32_t w, uint32_t h, veisp_color_format f);

void veavc_select_subengine(void);
void veavc_init_vle(struct ve_mem * J_mem, uint32_t size);
void veavc_init_ctrl(veavc_encoder_mode mode);
void veavc_jpeg_parameters(uint8_t fill1, uint8_t stuff, uint32_t biasY, uint32_t biasC);
void veavc_put_bits(uint8_t nbits, uint32_t data);
void veavc_sdram_index(uint32_t index);
void veavc_jpeg_quantization(uint16_t *tableY, uint16_t *tableC, uint32_t length);
void veavc_launch_encoding(void);
void veavc_check_status(void);
uint32_t veavc_get_written(void);

#endif

