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


#define PCODE_COMPLEX_LOGIC(typ)					\
  typ pcode_##typ##_complexLogic(					\
				 typ a,					\
				 typ b,					\
				 typ c,					\
				 typ d,					\
				 typ e,					\
				 typ f) {				\
    typ ret = 0;							\
    									\
    if (a > b && b > c || d < e && f < e) {				\
      ret += 1;								\
    }									\
    if (a != b || a != c && d != e || f != e) {				\
      ret += 2;								\
    }									\
    if (a && b && c || d && e && f) {					\
      ret += 4;								\
    }									\
    if (a || b || c && d || e || f) {					\
      ret += 8;								\
    }									\
    return ret;								\
  }

#define PCODE_BIOP_CMP(typ)			\
  typ biopCmp##typ####typ(			\
			  typ lhs,		\
			  typ rhs) {		\
    if (lhs < rhs)				\
      lhs += 2;					\
    if (lhs > rhs)				\
      lhs += 4;					\
    if (lhs == 0)				\
      lhs += 8;					\
    if (lhs != rhs)				\
      lhs += 16;				\
    return lhs;					\
  }

#define PCODE_BIOP_SUB(typ)			\
  typ biopSub##typ####typ(			\
			  typ lhs,		\
			  typ rhs) {		\
    typ z;					\
    z = lhs - rhs;				\
    return z;					\
  }

#define PCODE_BIOP_ADD(typ)			\
  typ biopAdd##typ####typ(			\
			  typ lhs,		\
			  typ rhs) {		\
    typ z;					\
    z = lhs + rhs;				\
    return z;					\
  }

#define PCODE_BIOP_AND(typ)			\
  typ biopAnd##typ####typ(			\
			  typ lhs,		\
			  typ rhs) {		\
    typ z;					\
    z = lhs & rhs;				\
    return z;					\
  }

#define PCODE_BIOP_OR(typ)			\
  typ biopOr##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs | rhs;				\
    return z;					\
  }


#define PCODE_BIOP_LOGIC_AND(typ)		\
  typ biopLogicAnd##typ####typ(			\
			       typ lhs,		\
			       typ rhs) {	\
    typ z;					\
    z = lhs && rhs;				\
    return z;					\
  }

#define PCODE_BIOP_LOGIC_OR(typ)		\
  typ biopLogicOr##typ####typ(			\
			      typ lhs,		\
			      typ rhs) {	\
    typ z;					\
    z = lhs || rhs;				\
    return z;					\
  }


#define PCODE_BIOP_LE(typ)			\
  typ biopLe##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs <= rhs;				\
    return z;					\
  }

#define PCODE_BIOP_LT(typ)			\
  typ biopLt##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs < rhs;				\
    return z;					\
  }


#define PCODE_BIOP_GE(typ)			\
  typ biopGe##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs >= rhs;				\
    return z;					\
  }

#define PCODE_BIOP_GT(typ)			\
  typ biopGt##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs > rhs;				\
    return z;					\
  }

#define PCODE_BIOP_EQ(typ)			\
  typ biopEq##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs == rhs;				\
    return z;					\
  }

#define PCODE_BIOP_NE(typ)			\
  typ biopNe##typ####typ(			\
			 typ lhs,		\
			 typ rhs) {		\
    typ z;					\
    z = lhs != rhs;				\
    return z;					\
  }

#define PCODE_BIOP_XOR(typ)			\
  typ biopXOr##typ####typ(			\
			  typ lhs,		\
			  typ rhs) {		\
    typ z;					\
    z = lhs ^ rhs;				\
    return z;					\
  }

#define PCODE_BIOP_SHL(typ)			\
  typ biopShtLft##typ####typ(			\
			     typ lhs,		\
			     typ rhs) {		\
    typ z;					\
    z = lhs << rhs;				\
    return z;					\
  }

#define PCODE_BIOP_SHR(typ)			\
  typ biopShtRht##typ####typ(			\
			     typ lhs,		\
			     typ rhs) {		\
    typ z;					\
    z = lhs >> rhs;				\
    return z;					\
  }


#define PCODE_UNOP_NOT(typ)			\
  typ unopNot##typ(typ lhs) {			\
    typ z;					\
    z = !lhs;					\
    return z;					\
  }

#define PCODE_UNOP_POS(typ)			\
  typ unopPlus##typ(typ lhs) {			\
    typ z;					\
    z = +lhs;					\
    return z;					\
  }

#define PCODE_UNOP_NEG(typ)			\
  typ unopNegative##typ(typ lhs) {		\
    typ z;					\
    z = -lhs;					\
    return z;					\
  }

#define PCODE_BIOP_DIV(typ)			\
  typ biopDivid##typ####typ(			\
			    typ lhs,		\
			    typ rhs) {		\
    typ z;					\
    z = lhs / rhs;				\
    return z;					\
  }

#define PCODE_BIOP_REM(typ)			\
  typ biopRemainder##typ####typ(		\
				typ lhs,	\
				typ rhs) {	\
    typ z;					\
    z = lhs % rhs;				\
    return z;					\
  }

#define PCODE_BIOP_MUL(typ)			\
  typ biopMult##typ####typ(			\
			   typ lhs,		\
			   typ rhs) {		\
    typ z;					\
    z = lhs * rhs;				\
    return z;					\
  }


PCODE_BIOP_ADD(i1);
PCODE_BIOP_ADD(i2);
PCODE_BIOP_ADD(i4);
PCODE_BIOP_ADD(u1);
PCODE_BIOP_ADD(u2);
PCODE_BIOP_ADD(u4);

PCODE_BIOP_AND(i1);
PCODE_BIOP_AND(i2);
PCODE_BIOP_AND(i4);
PCODE_BIOP_AND(u1);
PCODE_BIOP_AND(u2);
PCODE_BIOP_AND(u4);

PCODE_BIOP_CMP(i1);
PCODE_BIOP_CMP(i2);
PCODE_BIOP_CMP(i4);
PCODE_BIOP_CMP(u1);
PCODE_BIOP_CMP(u2);
PCODE_BIOP_CMP(u4);

PCODE_BIOP_EQ(i1);
PCODE_BIOP_EQ(i2);
PCODE_BIOP_EQ(i4);
PCODE_BIOP_EQ(u1);
PCODE_BIOP_EQ(u2);
PCODE_BIOP_EQ(u4);

PCODE_BIOP_GE(i1);
PCODE_BIOP_GE(i2);
PCODE_BIOP_GE(i4);
PCODE_BIOP_GE(u1);
PCODE_BIOP_GE(u2);
PCODE_BIOP_GE(u4);

PCODE_BIOP_GT(i1);
PCODE_BIOP_GT(i2);
PCODE_BIOP_GT(i4);
PCODE_BIOP_GT(u1);
PCODE_BIOP_GT(u2);
PCODE_BIOP_GT(u4);

PCODE_BIOP_LE(i1);
PCODE_BIOP_LE(i2);
PCODE_BIOP_LE(i4);
PCODE_BIOP_LE(u1);
PCODE_BIOP_LE(u2);
PCODE_BIOP_LE(u4);

PCODE_BIOP_LOGIC_AND(i1);
PCODE_BIOP_LOGIC_AND(i2);
PCODE_BIOP_LOGIC_AND(i4);
PCODE_BIOP_LOGIC_AND(u1);
PCODE_BIOP_LOGIC_AND(u2);
PCODE_BIOP_LOGIC_AND(u4);

PCODE_BIOP_LOGIC_OR(i1);
PCODE_BIOP_LOGIC_OR(i2);
PCODE_BIOP_LOGIC_OR(i4);
PCODE_BIOP_LOGIC_OR(u1);
PCODE_BIOP_LOGIC_OR(u2);
PCODE_BIOP_LOGIC_OR(u4);

PCODE_BIOP_LT(i1);
PCODE_BIOP_LT(i2);
PCODE_BIOP_LT(i4);
PCODE_BIOP_LT(u1);
PCODE_BIOP_LT(u2);
PCODE_BIOP_LT(u4);

PCODE_BIOP_NE(i1);
PCODE_BIOP_NE(i2);
PCODE_BIOP_NE(i4);
PCODE_BIOP_NE(u1);
PCODE_BIOP_NE(u2);
PCODE_BIOP_NE(u4);

PCODE_BIOP_OR(i1);
PCODE_BIOP_OR(i2);
PCODE_BIOP_OR(i4);
PCODE_BIOP_OR(u1);
PCODE_BIOP_OR(u2);
PCODE_BIOP_OR(u4);

PCODE_BIOP_SHL(i1);
PCODE_BIOP_SHL(i2);
PCODE_BIOP_SHL(i4);
PCODE_BIOP_SHL(u1);
PCODE_BIOP_SHL(u2);
PCODE_BIOP_SHL(u4);

PCODE_BIOP_SHR(i1);
PCODE_BIOP_SHR(i2);
PCODE_BIOP_SHR(i4);
PCODE_BIOP_SHR(u1);
PCODE_BIOP_SHR(u2);
PCODE_BIOP_SHR(u4);

PCODE_BIOP_SUB(i1);
PCODE_BIOP_SUB(i2);
PCODE_BIOP_SUB(i4);
PCODE_BIOP_SUB(u1);
PCODE_BIOP_SUB(u2);
PCODE_BIOP_SUB(u4);

PCODE_BIOP_XOR(i1);
PCODE_BIOP_XOR(i2);
PCODE_BIOP_XOR(i4);
PCODE_BIOP_XOR(u1);
PCODE_BIOP_XOR(u2);
PCODE_BIOP_XOR(u4);

PCODE_COMPLEX_LOGIC(i1);
PCODE_COMPLEX_LOGIC(i2);
PCODE_COMPLEX_LOGIC(i4);
PCODE_COMPLEX_LOGIC(u1);
PCODE_COMPLEX_LOGIC(u2);
PCODE_COMPLEX_LOGIC(u4);

PCODE_UNOP_NEG(i1);
PCODE_UNOP_NEG(i2);
PCODE_UNOP_NEG(i4);
PCODE_UNOP_NEG(u1);
PCODE_UNOP_NEG(u2);
PCODE_UNOP_NEG(u4);

PCODE_UNOP_NOT(i1);
PCODE_UNOP_NOT(i2);
PCODE_UNOP_NOT(i4);
PCODE_UNOP_NOT(u1);
PCODE_UNOP_NOT(u2);
PCODE_UNOP_NOT(u4);

PCODE_UNOP_POS(i1);
PCODE_UNOP_POS(i2);
PCODE_UNOP_POS(i4);
PCODE_UNOP_POS(u1);
PCODE_UNOP_POS(u2);
PCODE_UNOP_POS(u4);

#ifdef HAS_MULTIPLY

PCODE_BIOP_MUL(i1);
PCODE_BIOP_MUL(i2);
PCODE_BIOP_MUL(i4);
PCODE_BIOP_MUL(u1);
PCODE_BIOP_MUL(u2);
PCODE_BIOP_MUL(u4);

#endif /* HAS_MULTIPLY */

#ifdef HAS_DIVIDE

PCODE_BIOP_DIV(i1);
PCODE_BIOP_DIV(i2);
PCODE_BIOP_DIV(i4);
PCODE_BIOP_DIV(u1);
PCODE_BIOP_DIV(u2);
PCODE_BIOP_DIV(u4);

PCODE_BIOP_REM(i1);
PCODE_BIOP_REM(i2);
PCODE_BIOP_REM(i4);
PCODE_BIOP_REM(u1);
PCODE_BIOP_REM(u2);
PCODE_BIOP_REM(u4);

#endif /* HAS_DIVIDE */


#ifdef HAS_LONGLONG

PCODE_BIOP_AND(i8);
PCODE_BIOP_ADD(u8);

PCODE_BIOP_CMP(i8);
PCODE_BIOP_CMP(u8);

PCODE_BIOP_EQ(i8);
PCODE_BIOP_EQ(u8);

PCODE_BIOP_GE(i8);
PCODE_BIOP_GE(u8);

PCODE_BIOP_GT(i8);
PCODE_BIOP_GT(u8);

PCODE_BIOP_LE(i8);
PCODE_BIOP_LE(u8);

PCODE_BIOP_LOGIC_AND(i8);
PCODE_BIOP_LOGIC_AND(u8);

PCODE_BIOP_LOGIC_OR(i8);
PCODE_BIOP_LOGIC_OR(u8);

PCODE_BIOP_LT(i8);
PCODE_BIOP_LT(u8);

PCODE_BIOP_NE(i8);
PCODE_BIOP_NE(u8);

PCODE_BIOP_OR(i8);
PCODE_BIOP_OR(u8);

PCODE_BIOP_SHL(i8);
PCODE_BIOP_SHL(u8);

PCODE_BIOP_SHR(i8);
PCODE_BIOP_SHR(u8);

PCODE_BIOP_SUB(i8);
PCODE_BIOP_SUB(u8);

PCODE_BIOP_XOR(i8);
PCODE_BIOP_XOR(u8);

PCODE_COMPLEX_LOGIC(i8);
PCODE_COMPLEX_LOGIC(u8);

PCODE_UNOP_NEG(i8);
PCODE_UNOP_NEG(u8);

PCODE_UNOP_NOT(i8);
PCODE_UNOP_NOT(u8);

PCODE_UNOP_POS(i8);
PCODE_UNOP_POS(u8);

#ifdef HAS_MULTIPLY

PCODE_BIOP_MUL(i8);
PCODE_BIOP_MUL(u8);

#endif /* #ifdef HAS_MULTIPLY */

#ifdef HAS_DIVIDE

PCODE_BIOP_DIV(i8);
PCODE_BIOP_DIV(u8);

PCODE_BIOP_REM(i8);
PCODE_BIOP_REM(u8);

#endif /* #ifdef HAS_DIVIDE */

#endif /* #ifdef HAS_LONGLONG */


#ifdef HAS_FLOAT

PCODE_BIOP_ADD(f4);

PCODE_BIOP_CMP(f4);

PCODE_BIOP_EQ(f4);

PCODE_BIOP_GE(f4);

PCODE_BIOP_GT(f4);

PCODE_BIOP_LE(f4);

PCODE_BIOP_LOGIC_OR(f4);

PCODE_BIOP_LOGIC_AND(f4);

PCODE_BIOP_LT(f4);

PCODE_BIOP_NE(f4);

PCODE_BIOP_SUB(f4);

PCODE_UNOP_NEG(f4);

PCODE_UNOP_NOT(f4);

PCODE_UNOP_POS(f4);

#ifdef HAS_MULTIPLY

PCODE_BIOP_MUL(f4);

#endif /* #ifdef HAS_MULTIPLY */

#endif /* #ifdef HAS_FLOAT */


#ifdef HAS_DOUBLE

PCODE_BIOP_ADD(f8);

PCODE_BIOP_CMP(f8);

PCODE_BIOP_EQ(f8);

PCODE_BIOP_GE(f8);

PCODE_BIOP_GT(f8);

PCODE_BIOP_LE(f8);

PCODE_BIOP_LOGIC_OR(f8);

PCODE_BIOP_LOGIC_AND(f8);

PCODE_BIOP_LT(f8);

PCODE_BIOP_NE(f8);

PCODE_BIOP_SUB(f8);

PCODE_UNOP_NEG(f8);

PCODE_UNOP_NOT(f8);

PCODE_UNOP_POS(f8);

#ifdef HAS_MULTIPLY

PCODE_BIOP_MUL(f8);

#endif /* #ifdef HAS_MULTIPLY */

#endif /* #ifdef HAS_DOUBLE */
