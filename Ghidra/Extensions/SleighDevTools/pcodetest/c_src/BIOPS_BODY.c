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


#define PCODE_BIOP_CMP(typ)		\
typ typ##_compareLogic(		\
			typ lhs,	\
			typ rhs)	\
{					\
        typ z = 0;\
	if (lhs < 0)			\
		z += 1;		\
	if (lhs > 0)			\
		z += 2;		\
	if (lhs < rhs)			\
		z += 4;		\
	if (lhs > rhs)			\
		z += 8;		\
	if (lhs == 0)			\
		z += 16;		\
	if (lhs != rhs)		\
		z += 32;		\
	if (lhs == rhs)		\
		z += 64;		\
	return z;			\
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

#define PCODE_BIOP_LOGIC_OR(typ)	\
typ typ##_logicalOr(			\
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

#define PCODE_UNOP_NOT(typ)		\
typ typ##_logicalNot(typ lhs)		\
{					\
	typ z;				\
	z = !lhs;			\
	return z;			\
}

#define PCODE_UNOP_POSITIVE(typ)		\
typ typ##_unaryPositive(typ lhs)		\
{					\
	typ z;				\
	z = +lhs;			\
	return z;			\
}

#define PCODE_UNOP_NEGATIVE(typ)		\
typ typ##_unaryNegative(typ lhs)		\
{					\
	typ z;				\
	z = -lhs;			\
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

#define PCODE_COND_GT(typ)		\
u1 typ##_conditionGT(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs > rhs);		\
	return z;			\
}

#define PCODE_COND_GTZero(typ)			\
u1 typ##_conditionGTZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val > 0);		\
	return z;			\
}

#define PCODE_COND_GTOne(typ)			\
u1 typ##_conditionGTOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val > 1);		\
	return z;			\
}

#define PCODE_COND_GE(typ)		\
u1 typ##_conditionGE(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs >= rhs);		\
	return z;			\
}

#define PCODE_COND_GEZero(typ)			\
u1 typ##_conditionGEZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val >= 0);		\
	return z;			\
}

#define PCODE_COND_GEOne(typ)			\
u1 typ##_conditionGEOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val >= 1);		\
	return z;			\
}

#define PCODE_COND_EQ(typ)		\
u1 typ##_conditionEQ(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs == rhs);		\
	return z;			\
}

#define PCODE_COND_EQZero(typ)			\
u1 typ##_conditionEQZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val == 0);		\
	return z;			\
}

#define PCODE_COND_EQOne(typ)			\
u1 typ##_conditionEQOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val == 1);		\
	return z;			\
}

#define PCODE_COND_LE(typ)		\
u1 typ##_conditionLE(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs <= rhs);		\
	return z;			\
}

#define PCODE_COND_LEZero(typ)			\
u1 typ##_conditionLEZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val <= 0);		\
	return z;			\
}

#define PCODE_COND_LEOne(typ)			\
u1 typ##_conditionLEOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val <= 1);		\
	return z;			\
}

#define PCODE_COND_LT(typ)		\
u1 typ##_conditionLT(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs < rhs);		\
	return z;			\
}

#define PCODE_COND_LTZero(typ)			\
u1 typ##_conditionLTZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val < 0);		\
	return z;			\
}

#define PCODE_COND_LTOne(typ)		\
u1 typ##_conditionLTOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val < 1);		\
	return z;			\
}

#define PCODE_COND_NE(typ)		\
u1 typ##_conditionNE(			\
			typ lhs,	\
			typ rhs)	\
{					\
	u1 z;				\
	z = (u1)(lhs != rhs);		\
	return z;			\
}

#define PCODE_COND_NEZero(typ)			\
u1 typ##_conditionNEZero(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val != 0);		\
	return z;			\
}

#define PCODE_COND_NEOne(typ)			\
u1 typ##_conditionNEOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val != 1);		\
	return z;			\
}




#define PCODE_BIOPS(typ)					\
  PCODE_BIOP_ADD(typ)					\
  PCODE_BIOP_ADDZERO(typ)				\
  PCODE_BIOP_ADDONE(typ)				\
  PCODE_BIOP_AND(typ)					\
  PCODE_BIOP_ANDZERO(typ)				\
  PCODE_BIOP_ANDONE(typ)				\
  PCODE_BIOP_OR(typ)					\
  PCODE_BIOP_ORZERO(typ)				\
  PCODE_BIOP_ORONE(typ)				\
  PCODE_BIOP_SHL(typ)					\
  PCODE_BIOP_SHLZERO(typ)				\
  PCODE_BIOP_SHLONE(typ)				\
  PCODE_BIOP_SHR(typ)					\
  PCODE_BIOP_SHRZERO(typ)				\
  PCODE_BIOP_SHRONE(typ)				\
  PCODE_BIOP_SUB(typ)					\
  PCODE_BIOP_SUBZERO(typ)				\
  PCODE_BIOP_SUBONE(typ)				\
  PCODE_BIOP_XOR(typ)					\
  PCODE_BIOP_XORZERO(typ)				\
  PCODE_BIOP_XORONE(typ)				\
  PCODE_UNOP_POSITIVE(typ)					\
  PCODE_UNOP_NOT(typ)					\
  PCODE_UNOP_NEGATIVE(typ)					\
  PCODE_COMPLEX_LOGIC(typ)				\
  PCODE_BIOP_LOGIC_OR(typ)				\
  PCODE_BIOP_LOGIC_AND(typ)				\
  PCODE_BIOP_CMP(typ)					\
  PCODE_BIOP_MUL(typ)					\
  PCODE_BIOP_MULZERO(typ)				\
  PCODE_BIOP_MULONE(typ)				\
  PCODE_BIOP_DIV(typ)					\
  PCODE_BIOP_DIVZERO(typ)				\
  PCODE_BIOP_DIVONE(typ)				\
  PCODE_BIOP_REM(typ)					\
  PCODE_BIOP_REMZERO(typ)				\
  PCODE_BIOP_REMONE(typ)				\
  PCODE_COND_GT(typ)					\
  PCODE_COND_GTZero(typ)				\
  PCODE_COND_GTOne(typ)					\
  PCODE_COND_GE(typ)					\
  PCODE_COND_GEZero(typ)				\
  PCODE_COND_GEOne(typ)					\
  PCODE_COND_EQ(typ)					\
  PCODE_COND_EQZero(typ)				\
  PCODE_COND_EQOne(typ)					\
  PCODE_COND_LE(typ)					\
  PCODE_COND_LEZero(typ)				\
  PCODE_COND_LEOne(typ)					\
  PCODE_COND_LT(typ)					\
  PCODE_COND_LTZero(typ)				\
  PCODE_COND_LTOne(typ)					\
  PCODE_COND_NE(typ)					\
  PCODE_COND_NEZero(typ)				\
  PCODE_COND_NEOne(typ)



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


#define PCODE_BIOPS_FP(typ)					\
  PCODE_BIOP_ADD(typ)					\
  PCODE_BIOP_ADDZERO(typ)				\
  PCODE_BIOP_ADDONE(typ)				\
  PCODE_BIOP_SUB(typ)					\
  PCODE_BIOP_SUBZERO(typ)				\
  PCODE_BIOP_SUBONE(typ)				\
  PCODE_UNOP_POSITIVE(typ)					\
  PCODE_UNOP_NOT(typ)					\
  PCODE_UNOP_NEGATIVE(typ)					\
  PCODE_COMPLEX_LOGIC(typ)				\
  PCODE_BIOP_LOGIC_OR(typ)				\
  PCODE_BIOP_LOGIC_AND(typ)				\
  PCODE_BIOP_CMP(typ)					\
  PCODE_BIOP_MUL(typ)					\
  PCODE_BIOP_MULZERO(typ)				\
  PCODE_BIOP_MULONE(typ)				\
  PCODE_BIOP_DIV(typ)					\
  PCODE_BIOP_DIVZERO(typ)				\
  PCODE_BIOP_DIVONE(typ)				\
  PCODE_COND_GT(typ)					\
  PCODE_COND_GTZero(typ)				\
  PCODE_COND_GTOne(typ)					\
  PCODE_COND_GE(typ)					\
  PCODE_COND_GEZero(typ)				\
  PCODE_COND_GEOne(typ)					\
  PCODE_COND_EQ(typ)					\
  PCODE_COND_EQZero(typ)				\
  PCODE_COND_EQOne(typ)					\
  PCODE_COND_LE(typ)					\
  PCODE_COND_LEZero(typ)				\
  PCODE_COND_LEOne(typ)					\
  PCODE_COND_LT(typ)					\
  PCODE_COND_LTZero(typ)				\
  PCODE_COND_LTOne(typ)					\
  PCODE_COND_NE(typ)					\
  PCODE_COND_NEZero(typ)				\
  PCODE_COND_NEOne(typ)
  

#ifdef HAS_FLOAT
PCODE_BIOPS_FP(f4)
#endif /* #ifdef HAS_FLOAT */


#ifdef HAS_DOUBLE
PCODE_BIOPS_FP(f8)
#endif /* #ifdef HAS_DOUBLE */
