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
#include "ve.h"
#include "vepoc.h"

void picture_generate(uint32_t w, uint32_t h, uint8_t * Y, uint8_t * C)
{
    int x;
    int y;
    int b;
    int m;
    int w2 = w / 2;
    int w4 = w / 4;

    for (y = 0; y < h; y++)
        for (x = 0; x < w; x++) {
            b = w * y + x;
            m = y / 16;
            if (x % 16 && y % 16)
                if (m < 12)
                    Y[b] = 0x10 + 0x30 * (x / w4);
                else
                    Y[b] = 0x20 + 0xc0 * x / w;
            else
                Y[b] = 0xf0;
        }

    for (y = 0; y < h; y++)
        for (x = 0; x < w; x++) {
            b = w * y + x;
            m = y / 16;
            if (m < 4)
                C[b] = 0x80;
            else if (m == 4)
                if (x / w2)
                    C[b] = (x % 2) ? 0x30 : 0xc0;
                else
                    C[b] = (x % 2) ? 0xc0 : 0x30;
            else if (m == 5)
                if (x / w2)
                    C[b] = (x % 2) ? 0x80 : 0x10;
                else
                    C[b] = (x % 2) ? 0x80 : 0xf0;
            else
                C[b] = 0x20 + 0xc0 * x / w;
        }
}
