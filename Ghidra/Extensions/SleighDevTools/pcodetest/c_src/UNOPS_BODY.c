/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pcode_test.h"

#define I_AM_LITTLE (((union { unsigned x; unsigned char c; }){1}).c)


#define PCODE_UNOP_NOT(typ)		\
typ typ##_logicalNot(typ val)		\
{					\
	typ z;				\
	z = !val;			\
	return z;			\
}

#define PCODE_UNOP_COMP(typ)	       	\
typ typ##_unaryComp(typ val) \
{						\
    typ z;					\
    z = ~val;					\
    return z;					\
}

#define PCODE_UNOP_POSITIVE(typ)		\
typ typ##_unaryPositive(typ val)		\
{					\
	typ z;				\
	z = +val;			\
	return z;			\
}

#define PCODE_UNOP_NEGATIVE(typ)		\
  typ typ##_unaryNegative(typ val)		\
{					\
	typ z;				\
	z = -val;			\
	return z;			\
}

#define PCODE_UNOP_INCPRE(typ)			\
typ typ##_unaryIncPre(typ val) \
{						\
    typ z;					\
    z = ++val;					\
    return z;					\
}

#define PCODE_UNOP_INCPOST(typ)			\
typ typ##_unaryIncPost(typ val) \
{						\
    typ z;					\
    z = val++;       				\
    return z;					\
}

#define PCODE_UNOP_DECPRE(typ)			\
typ typ##_unaryDecPre(typ val) \
{						\
    typ z;					\
    z = --val;					\
    return z;					\
}

#define PCODE_UNOP_DECPOST(typ)			\
typ typ##_unaryDecPost(typ val) \
{						\
    typ z;					\
    z = val--;       				\
    return z;					\
}

u2 u2_swapRef(u2 val)
{
  u2 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = (x[0] << 8) |
      (x[1] << 0);
  else
    z = (x[1] << 8) |
      (x[0] << 0);

  return z;
}

u2 u2_swapMaskShift(u2 val)
{
  u2 z;
  z = ((val & 0xff00) >> 8) |
    ((val & 0x00ff) << 8);
  return z;
}

u2 u2_swapShiftMask(u2 val)
{
  u2 z;
  z = ((val >> 8) & 0x00ff) |
    ((val << 8) & 0xff00);
  return z;
}

i2 i2_swapRef(i2 val)
{
  i2 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = (x[0] << 8) |
      (x[1] << 0);
  else
    z = (x[1] << 8) |
      (x[0] << 0);

  return z;
}

i2 i2_swapMaskShift(i2 val)
{
  i2 z;
  z = ((val & 0xff00) >> 8) |
    ((val & 0x00ff) << 8);
  return z;
}

i2 i2_swapShiftMask(i2 val)
{
  i2 z;
  z = ((val >> 8) & 0x00ff) |
    ((val << 8) & 0xff00);
  return z;
}

u4 u4_swapRef(u4 val)
{
  u4 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = (x[0] << 24) |
      (x[1] << 16) |
      (x[2] << 8) |
      (x[3] << 0);
  else
    z = (x[3] << 24) |
      (x[2] << 16) |
      (x[1] << 8) |
      (x[0] << 0);

  return z;
}

u4 u4_swapMaskShift(u4 val)
{
  u4 z;
  z = ((val & 0xff000000) >> 24) |
    ((val & 0x00ff0000) >> 8) |
    ((val & 0x0000ff00) << 8) |
    ((val & 0x000000ff) << 24);
  return z;
}

u4 u4_swapShiftMask(u4 val)
{
  u4 z;
  z = ((val >> 24) & 0x000000ff) |
    ((val >> 8) & 0x0000ff00) |
    ((val << 8) & 0x00ff0000) |
    ((val << 24) & 0xff000000);
  return z;
}

u4 u4_swapMask(u4 val)
{
  u4 z = val;
  z = (z & 0x0000FFFF) << 16 | (z & 0xFFFF0000) >> 16;
  z = (z & 0x00FF00FF) << 8  | (z & 0xFF00FF00) >> 8;
  return z;
}

i4 i4_swapRef(i4 val)
{
  i4 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = (x[0] << 24) |
      (x[1] << 16) |
      (x[2] << 8) |
      (x[3] << 0);
  else
    z = (x[3] << 24) |
      (x[2] << 16) |
      (x[1] << 8) |
      (x[0] << 0);

  return z;
}

i4 i4_swapMaskShift(i4 val)
{
  i4 z;
  z = ((val & 0xff000000) >> 24) |
    ((val & 0x00ff0000) >> 8) |
    ((val & 0x0000ff00) << 8) |
    ((val & 0x000000ff) << 24);
  return z;
}

i4 i4_swapShiftMask(i4 val)
{
  i4 z;
  z = ((val >> 24) & 0x000000ff) |
    ((val >> 8) & 0x0000ff00) |
    ((val << 8) & 0x00ff0000) |
    ((val << 24) & 0xff000000);
  return z;
}

i4 i4_swapMask(i4 val)
{
  i4 z = val;
  z = (z & 0x0000FFFF) << 16 | (z & 0xFFFF0000) >> 16;
  z = (z & 0x00FF00FF) << 8  | (z & 0xFF00FF00) >> 8;
  return z;
}

#ifdef HAS_LONGLONG

u8 u8_swapRef(u8 val)
{
  u8 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = ((u8)x[0] << 56) |
      ((u8)x[1] << 48) |
      ((u8)x[2] << 40) |
      ((u8)x[3] << 32) |
      ((u8)x[4] << 24) |
      ((u8)x[5] << 16) |
      ((u8)x[6] << 8) |
      ((u8)x[7] << 0);
  else
    z = ((u8)x[7] << 56) |
      ((u8)x[6] << 48) |
      ((u8)x[5] << 40) |
      ((u8)x[4] << 32) |
      ((u8)x[3] << 24) |
      ((u8)x[2] << 16) |
      ((u8)x[1] << 8) |
      ((u8)x[0] << 0);

  return z;
}

u8 u8_swapMaskShift(u8 val)
{
  u8 z;
  z = ((val & 0xff00000000000000) >> 56) |
      ((val & 0x00ff000000000000) >> 40) |
      ((val & 0x0000ff0000000000) >> 24) |
      ((val & 0x000000ff00000000) >> 8) |
      ((val & 0x00000000ff000000) << 8) |
      ((val & 0x0000000000ff0000) << 24) |
      ((val & 0x000000000000ff00) << 40) |
      ((val & 0x00000000000000ff) << 56);
  return z;
}

u8 u8_swapShiftMask(u8 val)
{
  u8 z;
  z = ((val >> 56) & 0x00000000000000ff) |
      ((val >> 40) & 0x000000000000ff00) |
      ((val >> 24) & 0x0000000000ff0000) |
      ((val >>  8) & 0x00000000ff000000) |
      ((val <<  8) & 0x000000ff00000000) |
      ((val << 24) & 0x0000ff0000000000) |
      ((val << 40) & 0x00ff000000000000) |
      ((val << 56) & 0xff00000000000000);
  return z;
}

u8 u8_swapMask(u8 val)
{
  u8 z = val;
  z = (z & 0x00000000FFFFFFFF) << 32 | (z & 0xFFFFFFFF00000000) >> 32;
  z = (z & 0x0000FFFF0000FFFF) << 16 | (z & 0xFFFF0000FFFF0000) >> 16;
  z = (z & 0x00FF00FF00FF00FF) << 8  | (z & 0xFF00FF00FF00FF00) >> 8;
  return z;
}

i8 i8_swapRef(i8 val)
{
  i8 z;
  u1 *x = (u1 *)&val;
  if (I_AM_LITTLE)
    z = ((i8)x[0] << 56) |
      ((i8)x[1] << 48) |
      ((i8)x[2] << 40) |
      ((i8)x[3] << 32) |
      ((i8)x[4] << 24) |
      ((i8)x[5] << 16) |
      ((i8)x[6] << 8) |
      ((i8)x[7] << 0);
  else
    z = ((i8)x[7] << 56) |
      ((i8)x[6] << 48) |
      ((i8)x[5] << 40) |
      ((i8)x[4] << 32) |
      ((i8)x[3] << 24) |
      ((i8)x[2] << 16) |
      ((i8)x[1] << 8) |
      ((i8)x[0] << 0);

  return z;
}

i8 i8_swapMaskShift(i8 val)
{
  i8 z;
  z = ((val & 0xff00000000000000) >> 56) |
      ((val & 0x00ff000000000000) >> 40) |
      ((val & 0x0000ff0000000000) >> 24) |
      ((val & 0x000000ff00000000) >> 8) |
      ((val & 0x00000000ff000000) << 8) |
      ((val & 0x0000000000ff0000) << 24) |
      ((val & 0x000000000000ff00) << 40) |
      ((val & 0x00000000000000ff) << 56);
  return z;
}

i8 i8_swapShiftMask(i8 val)
{
  i8 z;
  z = ((val >> 56) & 0x00000000000000ff) |
      ((val >> 40) & 0x000000000000ff00) |
      ((val >> 24) & 0x0000000000ff0000) |
      ((val >>  8) & 0x00000000ff000000) |
      ((val <<  8) & 0x000000ff00000000) |
      ((val << 24) & 0x0000ff0000000000) |
      ((val << 40) & 0x00ff000000000000) |
      ((val << 56) & 0xff00000000000000);
  return z;
}

i8 i8_swapMask(i8 val)
{
  i8 z = val;
  z = (z & 0x00000000FFFFFFFF) << 32 | (z & 0xFFFFFFFF00000000) >> 32;
  z = (z & 0x0000FFFF0000FFFF) << 16 | (z & 0xFFFF0000FFFF0000) >> 16;
  z = (z & 0x00FF00FF00FF00FF) << 8  | (z & 0xFF00FF00FF00FF00) >> 8;
  return z;
}

#endif /* #ifdef HAS_LONGLONG */

#define PCODE_UNOPS(typ)			\
	PCODE_UNOP_POSITIVE(typ)		\
	PCODE_UNOP_NOT(typ)			\
	PCODE_UNOP_NEGATIVE(typ)		\
	PCODE_UNOP_COMP(typ)			\
	PCODE_UNOP_INCPRE(typ)			\
	PCODE_UNOP_INCPOST(typ)			\
	PCODE_UNOP_DECPRE(typ)			\
	PCODE_UNOP_DECPOST(typ)


PCODE_UNOPS(u1)
PCODE_UNOPS(i1)
PCODE_UNOPS(u2)
PCODE_UNOPS(i2)
PCODE_UNOPS(u4)
PCODE_UNOPS(i4)


#ifdef HAS_LONGLONG
PCODE_UNOPS(u8)
PCODE_UNOPS(i8)
#endif /* #ifdef HAS_LONGLONG */


#define PCODE_UNOPS_FP(typ)\
	PCODE_UNOP_POSITIVE(typ)		\
	PCODE_UNOP_NOT(typ)			\
	PCODE_UNOP_NEGATIVE(typ)		\
	PCODE_UNOP_INCPRE(typ)			\
	PCODE_UNOP_INCPOST(typ)			\
	PCODE_UNOP_DECPRE(typ)			\
	PCODE_UNOP_DECPOST(typ)

#ifdef HAS_FLOAT
PCODE_UNOPS_FP(f4)
#endif /* #ifdef HAS_FLOAT */


#ifdef HAS_DOUBLE
PCODE_UNOPS_FP(f8)
#endif /* #ifdef HAS_DOUBLE */
