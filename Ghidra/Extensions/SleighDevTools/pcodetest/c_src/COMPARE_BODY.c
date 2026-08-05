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

#define PCODE_BIOP_COND(typ)		\
typ typ##_conditionLogic(		\
			typ lhs,	\
			typ rhs,	\
			typ val0,	\
			typ val1,	\
			typ val2,	\
			typ val3,	\
			typ val4,	\
			typ val5,	\
			typ val6)	\
{					\
  typ z = val0;				\
  if (lhs < rhs)			\
    z = z + val1;				\
  if (lhs > rhs)			\
    z = z - val2;				\
  if (lhs != rhs)			\
    z = z * val3;				\
  if (lhs == rhs)			\
    z = z / val4;				\
  if (lhs <= rhs)			\
    z = z ^ val5;				\
  if (lhs >= rhs)			\
    z = z | val6;				\
  return z;				\
}

#define PCODE_BIOP_CONDZERO(typ)		\
typ typ##_conditionLogicZero(		\
			typ val,	\
			typ val0,	\
			typ val1,	\
			typ val2,	\
			typ val3,	\
			typ val4,	\
			typ val5,	\
			typ val6)	\
{					\
	typ z = val0;			\
	if (val1 < 0)			\
		z = z + val;		\
	if (val2 > 0)			\
		z = z - val;		\
	if (val3 != 0)			\
		z = z * val;		\
	if (val4 == 0)			\
		z = z / val;		\
	if (val5 <= 0)			\
		z = z ^ val;		\
	if (val6 >= 0)			\
		z = z | val;		\
	return z;			\
}

#define PCODE_BIOP_CONDONE(typ)		\
typ typ##_conditionLogicOne(		\
			typ val,	\
			typ val0,	\
			typ val1,	\
			typ val2,	\
			typ val3,	\
			typ val4,	\
			typ val5,	\
			typ val6)	\
{					\
	typ z = val0;			\
	if (val < 1)			\
		z = z + val1;		\
	if (val > 1)			\
		z = z - val2;		\
	if (val != 1)			\
		z = z * val3;		\
	if (val == 1)			\
		z = z / val4;		\
	if (val <= 1)			\
		z = z ^ val5;		\
	if (val >= 1)			\
		z = z | val6;		\
	return z;			\
}

#define PCODE_BIOP_CONDNEGONE(typ)	\
typ typ##_conditionLogicNegOne(		\
			typ val,	\
			typ val0,	\
			typ val1,	\
			typ val2,	\
			typ val3,	\
			typ val4,	\
			typ val5,	\
			typ val6)	\
{					\
	typ z = val0;			\
	if (val < (typ)-1)     		\
		z = z + val1;		\
	if (val > (typ)-1)     		\
		z = z - val2;		\
	if (val != (typ)-1)	       	\
		z = z * val3;		\
	if (val == (typ)-1)	       	\
		z = z / val4;		\
	if (val <= (typ)-1)    		\
		z = z ^ val5;		\
	if (val >= (typ)-1)	       	\
		z = z | val6;		\
	return z;			\
}

#define PCODE_BIOP_MAX(typ)		\
typ typ##_maximumNew(			\
		typ lhs,		\
		typ rhs)		\
{					\
	typ z;				\
	z = lhs > rhs ? lhs : rhs;	\
	return z;			\
}					\
typ typ##_maximum(			\
		typ lhs,		\
		typ rhs)		\
{					\
	typ z;				\
	z = lhs >= rhs ? lhs : rhs;	\
	return z;			\
}

#define PCODE_BIOP_MIN(typ)		\
typ typ##_minimumNew(			\
		typ lhs,		\
		typ rhs)		\
{					\
	typ z;				\
	z = lhs < rhs ? lhs : rhs;	\
	return z;			\
}					\
typ typ##_minimum(			\
		typ lhs,		\
       		typ rhs)		\
{					\
	typ z;				\
	z = lhs <= rhs ? lhs : rhs;	\
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

#define PCODE_COND_GTUNUSED(typ)		\
  u1 typ##_conditionGTUnused(UNUSED typ val,	\
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

#define PCODE_COND_GTNegOne(typ)       	\
u1 typ##_conditionGTNegOne(		\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val > (typ)-1);       	\
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

#define PCODE_COND_GEUNUSED(typ)		\
  u1 typ##_conditionGEUnused(UNUSED typ val,	\
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

#define PCODE_COND_GENegOne(typ)			\
u1 typ##_conditionGENegOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val >= (typ)-1);		\
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

#define PCODE_COND_EQUNUSED(typ)		\
  u1 typ##_conditionEQUnused(UNUSED typ val,	\
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

#define PCODE_COND_EQNegOne(typ)			\
u1 typ##_conditionEQNegOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val == (typ)-1);		\
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

#define PCODE_COND_LEUNUSED(typ)		\
  u1 typ##_conditionLEUnused(UNUSED typ val,	\
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

#define PCODE_COND_LENegOne(typ)			\
u1 typ##_conditionLENegOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val <= (typ)-1);		\
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

#define PCODE_COND_LTUNUSED(typ)		\
  u1 typ##_conditionLTUnused(UNUSED typ val,	\
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

#define PCODE_COND_LTNegOne(typ)		\
u1 typ##_conditionLTNegOne(			\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val < (typ)-1);		\
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

#define PCODE_COND_NEUNUSED(typ)		\
  u1 typ##_conditionNEUnused(UNUSED typ val,	\
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

#define PCODE_COND_NENegOne(typ)	\
u1 typ##_conditionNENegOne(		\
			typ val)	\
{					\
	u1 z;				\
	z = (u1)(val != (typ)-1);	\
	return z;			\
}


#define PCODE_COND_COMPEQZERO(typ)	\
typ typ##_conditionCompEqZero(typ val,	\
			      typ lhs,	\
			      typ rhs)	\
{					\
	return val == 0 ? lhs : rhs;	\
}

#define PCODE_COND_COMPNEZERO(typ)	\
typ typ##_conditionCompNeZero(typ val,	\
			      typ lhs,	\
			      typ rhs)	\
{					\
	return val != 0 ? lhs : rhs;	\
}

#define PCODE_COND_COMPEQNEGONE(typ)	\
typ typ##_conditionCompEqNegOne(typ val,	\
			      typ lhs,	\
			      typ rhs)	\
{					\
	return val == (typ)-1 ? lhs : rhs;	\
}

#define PCODE_COND_COMPNENEGONE(typ)	\
typ typ##_conditionCompNeNegOne(typ val,	\
			      typ lhs,	\
			      typ rhs)	\
{					\
	return val != (typ)-1 ? lhs : rhs;	\
}

#define PCODE_COND_COMPIMMEQZERO(typ)	\
typ typ##_conditionCompImmEqZero(typ val,	\
				 typ lhs)	\
{					\
	return val == 0 ? lhs : 5;	\
}

#define PCODE_COND_COMPIMMNEZERO(typ)	\
typ typ##_conditionCompImmNeZero(typ val,	\
				 typ lhs)	\
{					\
	return val != 0 ? lhs : 5;	\
}

#define PCODE_COND_COMPIMMEQNEGONE(typ)	\
typ typ##_conditionCompImmEqNegOne(typ val,	\
				   typ lhs)	\
{					\
	return val == (typ)-1 ? lhs : 5;	\
}

#define PCODE_COND_COMPIMMNENEGONE(typ)	\
typ typ##_conditionCompImmNeNegOne(typ val,	\
				   typ lhs)	\
{					\
	return val != (typ)-1 ? lhs : 5;	\
}



#define PCODE_COMPARE(typ)			\
	PCODE_BIOP_CMP(typ)			\
	PCODE_COND_GT(typ)			\
	PCODE_COND_GTUNUSED(typ)		\
	PCODE_COND_GTZero(typ)			\
	PCODE_COND_GTOne(typ)			\
	PCODE_COND_GTNegOne(typ)		\
	PCODE_COND_GE(typ)			\
	PCODE_COND_GEUNUSED(typ)		\
	PCODE_COND_GEZero(typ)			\
	PCODE_COND_GEOne(typ)			\
	PCODE_COND_GENegOne(typ)	       	\
	PCODE_COND_EQ(typ)			\
	PCODE_COND_EQUNUSED(typ)		\
	PCODE_COND_EQZero(typ)			\
	PCODE_COND_EQOne(typ)			\
	PCODE_COND_EQNegOne(typ)	       	\
	PCODE_COND_LE(typ)			\
	PCODE_COND_LEUNUSED(typ)		\
	PCODE_COND_LEZero(typ)			\
	PCODE_COND_LEOne(typ)			\
	PCODE_COND_LENegOne(typ)	       	\
	PCODE_COND_LT(typ)			\
	PCODE_COND_LTUNUSED(typ)		\
	PCODE_COND_LTZero(typ)			\
	PCODE_COND_LTOne(typ)			\
	PCODE_COND_LTNegOne(typ)	       	\
	PCODE_COND_NE(typ)			\
	PCODE_COND_NEUNUSED(typ)		\
	PCODE_COND_NEZero(typ)			\
	PCODE_COND_NEOne(typ)			\
	PCODE_COND_NENegOne(typ)	       	\
	PCODE_BIOP_MAX(typ)			\
	PCODE_BIOP_MIN(typ)			\
	PCODE_BIOP_COND(typ)			\
	PCODE_BIOP_CONDZERO(typ)		\
	PCODE_BIOP_CONDONE(typ)			\
	PCODE_BIOP_CONDNEGONE(typ)		\
	PCODE_COND_COMPEQZERO(typ)		\
	PCODE_COND_COMPNEZERO(typ)		\
	PCODE_COND_COMPEQNEGONE(typ)		\
	PCODE_COND_COMPNENEGONE(typ)		\
	PCODE_COND_COMPIMMEQZERO(typ)		\
	PCODE_COND_COMPIMMNEZERO(typ)		\
	PCODE_COND_COMPIMMEQNEGONE(typ)		\
	PCODE_COND_COMPIMMNENEGONE(typ)		\


PCODE_COMPARE(u1)
PCODE_COMPARE(i1)
PCODE_COMPARE(u2)
PCODE_COMPARE(i2)
PCODE_COMPARE(u4)
PCODE_COMPARE(i4)

#ifdef HAS_LONGLONG
PCODE_COMPARE(u8)
PCODE_COMPARE(i8)
#endif /* #ifdef HAS_LONGLONG */


#define PCODE_COMPARE_FP(typ)			       	\
  PCODE_BIOP_CMP(typ)					\
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
PCODE_COMPARE_FP(f4)
#endif /* #ifdef HAS_FLOAT */


#ifdef HAS_DOUBLE
PCODE_COMPARE_FP(f8)
#endif /* #ifdef HAS_DOUBLE */
