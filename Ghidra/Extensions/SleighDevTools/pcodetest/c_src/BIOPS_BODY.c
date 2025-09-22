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

#define PCODE_COMPLEX_LOGIC(typ)			\
typ typ##_complexLogic(				\
			typ a,				\
			typ b,				\
			typ c,				\
			typ d,				\
			typ e,				\
			typ f)				\
{							\
	typ ret = 0;					\
							\
	if (a > b && b > c || d < e && f < e)		\
		ret += 1;				\
	if (a != b || a != c && d != e || f != e)	\
		ret += 2;				\
	if (a && b && c || d && e && f)		\
		ret += 4;				\
	if (a || b || c && d || e || f)		\
		ret += 8;				\
	return ret;					\
}


#define PCODE_BIOP_SUB(typ)		\
typ typ##_subtract(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z;			\
}

#define PCODE_BIOP_SUBUNUSED(typ)		\
  typ typ##_subtractUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z;			\
}

#define PCODE_BIOP_SUBZERO(typ)		\
typ typ##_subtractZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 - val;			\
	return z;			\
}
#define PCODE_BIOP_SUBONE(typ)		\
typ typ##_subtractOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 - val;			\
	return z;			\
}

#define PCODE_BIOP_ADD(typ)		\
typ typ##_addition(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z;			\
}

#define PCODE_BIOP_ADDUNUSED(typ)		\
  typ typ##_additionUnused(UNUSED typ val,		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z;			\
}

#define PCODE_BIOP_ADDZERO(typ)		\
typ typ##_additionZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 + val;			\
	return z;			\
}

#define PCODE_BIOP_ADDONE(typ)		\
typ typ##_additionOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 + val;			\
	return z;			\
}

#define PCODE_BIOP_AND(typ)		\
typ typ##_bitwiseAnd(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z;			\
}

#define PCODE_BIOP_ANDUNUSED(typ)		\
  typ typ##_bitwiseAndUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z;			\
}

#define PCODE_BIOP_ANDZERO(typ)		\
typ typ##_bitwiseAndZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 & val;			\
	return z;			\
}

#define PCODE_BIOP_ANDONE(typ)		\
typ typ##_bitwiseAndOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 & val;			\
	return z;			\
}

#define PCODE_BIOP_OR(typ)		\
typ typ##_bitwiseOr(			\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z;			\
}

#define PCODE_BIOP_ORUNUSED(typ)		\
  typ typ##_bitwiseOrUnused(UNUSED typ val,	\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z;			\
}

#define PCODE_BIOP_ORZERO(typ)		\
typ typ##_bitwiseOrZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 | val;			\
	return z;			\
}

#define PCODE_BIOP_ORONE(typ)		\
typ typ##_bitwiseOrOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 | val;			\
	return z;			\
}


#define PCODE_BIOP_LOGIC_AND(typ)	\
typ typ##_logicalAnd(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs && rhs;		\
	return z;			\
}

#define PCODE_BIOP_LOGIC_ANDUNUSED(typ)	\
  typ typ##_logicalAndUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs && rhs;		\
	return z;			\
}

#define PCODE_BIOP_LOGIC_OR(typ)	\
typ typ##_logicalOr(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs || rhs;		\
	return z;			\
}

#define PCODE_BIOP_LOGIC_ORUNUSED(typ)	\
  typ typ##_logicalOrUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs || rhs;		\
	return z;			\
}

#define PCODE_BIOP_XOR(typ)		\
typ typ##_bitwiseXor(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z;			\
}

#define PCODE_BIOP_XORUNUSED(typ)		\
  typ typ##_bitwiseXorUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z;			\
}

#define PCODE_BIOP_XORZERO(typ)		\
typ typ##_bitwiseXorZoer(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 ^ val;			\
	return z;			\
}

#define PCODE_BIOP_XORONE(typ)		\
typ typ##_bitwiseXorOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 ^ val;			\
	return z;			\
}


#define PCODE_BIOP_SHL(typ)		\
typ typ##_shiftLeft(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z;			\
}

#define PCODE_BIOP_SHLUNUSED(typ)		\
  typ typ##_shiftLeftUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z;			\
}

#define PCODE_BIOP_SHLZERO(typ)		\
typ typ##_shiftLeftZero(			\
			typ val)	\
{					\
	typ z;				\
	z = val << 0;			\
	return z;			\
}

#define PCODE_BIOP_SHLONE(typ)		\
typ typ##_shiftLeftOne(			\
			typ val)	\
{					\
	typ z;				\
	z = val << 1;			\
	return z;			\
}

#define PCODE_BIOP_SHR(typ)		\
typ typ##_shiftRight(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z;			\
}

#define PCODE_BIOP_SHRUNUSED(typ)		\
  typ typ##_shiftRightUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z;			\
}

#define PCODE_BIOP_SHRZERO(typ)		\
typ typ##_shiftRightZero(			\
			typ val)	\
{					\
	typ z;				\
	z = val >> 0;			\
	return z;			\
}

#define PCODE_BIOP_SHRONE(typ)		\
typ typ##_shiftRightOne(			\
			typ val)	\
{					\
	typ z;				\
	z = val >> 1;			\
	return z;			\
}

#define PCODE_BIOP_DIV(typ)		\
typ typ##_divide(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs / rhs;			\
	return z;			\
}

#define PCODE_BIOP_DIVUNUSED(typ)		\
  typ typ##_divideUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs / rhs;			\
	return z;			\
}

#define PCODE_BIOP_DIVZERO(typ)		\
typ typ##_diviceZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 / val;			\
	return z;			\
}

#define PCODE_BIOP_DIVONE(typ)		\
typ typ##_divideOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 / val;			\
	return z;			\
}

#define PCODE_BIOP_REM(typ)		\
typ typ##_remainder(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs % rhs;			\
	return z;			\
}

#define PCODE_BIOP_REMUNUSED(typ)		\
  typ typ##_remainderUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs % rhs;			\
	return z;			\
}

#define PCODE_BIOP_REMZERO(typ)		\
typ typ##_remainderZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 % val;			\
	return z;			\
}

#define PCODE_BIOP_REMONE(typ)		\
typ typ##_remainderOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 % val;			\
	return z;			\
}

#define PCODE_BIOP_MUL(typ)		\
typ typ##_multiply(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z;			\
}

#define PCODE_BIOP_MULUNUSED(typ)		\
  typ typ##_multiplyUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z;			\
}

#define PCODE_BIOP_MULZERO(typ)		\
typ typ##_multiplyZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 * val;			\
	return z;			\
}

#define PCODE_BIOP_MULONE(typ)		\
typ typ##_multiplyOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 * val;			\
	return z;			\
}


#define PCODE_BIOPS(typ)			\
	PCODE_BIOP_ADD(typ)			\
	PCODE_BIOP_ADDUNUSED(typ)		\
	PCODE_BIOP_ADDZERO(typ)			\
	PCODE_BIOP_ADDONE(typ)			\
	PCODE_BIOP_AND(typ)			\
	PCODE_BIOP_ANDUNUSED(typ)		\
	PCODE_BIOP_ANDZERO(typ)			\
	PCODE_BIOP_ANDONE(typ)			\
	PCODE_BIOP_OR(typ)			\
	PCODE_BIOP_ORUNUSED(typ)		\
	PCODE_BIOP_ORZERO(typ)			\
	PCODE_BIOP_ORONE(typ)			\
	PCODE_BIOP_SHL(typ)			\
	PCODE_BIOP_SHLUNUSED(typ)		\
	PCODE_BIOP_SHLZERO(typ)			\
	PCODE_BIOP_SHLONE(typ)			\
	PCODE_BIOP_SHR(typ)			\
	PCODE_BIOP_SHRUNUSED(typ)		\
	PCODE_BIOP_SHRZERO(typ)			\
	PCODE_BIOP_SHRONE(typ)			\
	PCODE_BIOP_SUB(typ)			\
	PCODE_BIOP_SUBUNUSED(typ)		\
	PCODE_BIOP_SUBZERO(typ)			\
	PCODE_BIOP_SUBONE(typ)			\
	PCODE_BIOP_XOR(typ)			\
	PCODE_BIOP_XORUNUSED(typ)		\
	PCODE_BIOP_XORZERO(typ)			\
	PCODE_BIOP_XORONE(typ)			\
	PCODE_COMPLEX_LOGIC(typ)		\
	PCODE_BIOP_LOGIC_OR(typ)		\
	PCODE_BIOP_LOGIC_ORUNUSED(typ)		\
	PCODE_BIOP_LOGIC_AND(typ)		\
	PCODE_BIOP_LOGIC_ANDUNUSED(typ)		\
	PCODE_BIOP_MUL(typ)			\
	PCODE_BIOP_MULUNUSED(typ)		\
	PCODE_BIOP_MULZERO(typ)			\
	PCODE_BIOP_MULONE(typ)			\
	PCODE_BIOP_DIV(typ)			\
	PCODE_BIOP_DIVUNUSED(typ)		\
	PCODE_BIOP_DIVZERO(typ)			\
	PCODE_BIOP_DIVONE(typ)			\
	PCODE_BIOP_REM(typ)			\
	PCODE_BIOP_REMUNUSED(typ)		\
	PCODE_BIOP_REMZERO(typ)			\
	PCODE_BIOP_REMONE(typ)


PCODE_BIOPS(u1)
PCODE_BIOPS(i1)
PCODE_BIOPS(u2)
PCODE_BIOPS(i2)
PCODE_BIOPS(u4)
PCODE_BIOPS(i4)

#ifdef HAS_LONGLONG
PCODE_BIOPS(u8)
PCODE_BIOPS(i8)
#endif /* #ifdef HAS_LONGLONG */


#define PCODE_BIOPS_FP(typ)			\
	PCODE_BIOP_ADD(typ)			\
	PCODE_BIOP_ADDZERO(typ)			\
	PCODE_BIOP_ADDONE(typ)			\
	PCODE_BIOP_SUB(typ)			\
	PCODE_BIOP_SUBZERO(typ)			\
	PCODE_BIOP_SUBONE(typ)			\
	PCODE_COMPLEX_LOGIC(typ)		\
	PCODE_BIOP_LOGIC_OR(typ)		\
	PCODE_BIOP_LOGIC_AND(typ)		\
	PCODE_BIOP_MUL(typ)			\
	PCODE_BIOP_MULZERO(typ)			\
	PCODE_BIOP_MULONE(typ)			\
	PCODE_BIOP_DIV(typ)			\
	PCODE_BIOP_DIVZERO(typ)			\
	PCODE_BIOP_DIVONE(typ)
  

#ifdef HAS_FLOAT
PCODE_BIOPS_FP(f4)
#endif /* #ifdef HAS_FLOAT */


#ifdef HAS_DOUBLE
PCODE_BIOPS_FP(f8)
#endif /* #ifdef HAS_DOUBLE */
