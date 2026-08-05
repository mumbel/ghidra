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
}\
typ typ##_subtractImm(typ lhs)       	\
{					\
	typ z;				\
	z = lhs - 5;			\
	return z;			\
}

#define PCODE_BIOP_SUB_UF(typ)		\
typ typ##_subtractUnderflow(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z > lhs;			\
}\
typ typ##_subtractUnderflowImm(	       	\
			       typ lhs)	\
{					\
	typ z;				\
	z = lhs - 5;			\
	return z > lhs;			\
}


#define PCODE_BIOP_SUBEQZero(typ)		\
typ typ##_subtractEqZero(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z == 0;			\
}\
typ typ##_subtractEqZeroImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs - 5;			\
	return z == 0;			\
}


#define PCODE_BIOP_SUBNEZero(typ)		\
typ typ##_subtractNeZero(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z != 0;			\
}\
typ typ##_subtractNeZeroImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs - 5;			\
	return z != 0;			\
}


#define PCODE_BIOP_SUBUNUSED(typ)		\
typ typ##_subtractUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs - rhs;			\
	return z;			\
}\
typ typ##_subtractUnusedImm(UNUSED typ val,	\
			 typ lhs)		\
{					\
	typ z;				\
	z = lhs - 5;			\
	return z;			\
}

#define PCODE_BIOP_SUBZERO(typ)		\
typ typ##_subtractZero(			\
			typ val)	\
{					\
	typ z;				\
	z = 0 - val;			\
	return z;			\
}\

#define PCODE_BIOP_SUBONE(typ)		\
typ typ##_subtractOne(			\
			typ val)	\
{					\
	typ z;				\
	z = 1 - val;			\
	return z;			\
}

#define PCODE_BIOP_SUBNEGONE(typ)      	\
typ typ##_subtractNegOne(      		\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 - val;     		\
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
}\
typ typ##_additionImm(			\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs + 5;			\
	return z;			\
}

#define PCODE_BIOP_ADD_OV(typ)		\
typ typ##_additionOverflow(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z < lhs;			\
}\
typ typ##_additionOverflowImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs + 5;			\
	return z < lhs;			\
}

#define PCODE_BIOP_ADD_NOOV(typ)		\
typ typ##_additionNoOverflow(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z >= lhs;			\
}\
typ typ##_additionNoOverflowImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs + 5;			\
	return z > lhs;			\
}

#define PCODE_BIOP_ADDEQZero(typ)      	\
typ typ##_additionEqZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z == 0;			\
}\
typ typ##_additionEqZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs + 5;			\
	return z == 0;			\
}

#define PCODE_BIOP_ADDNEZero(typ)      	\
typ typ##_additionNeZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z != 0;			\
}\
typ typ##_additionNeZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs + 5;			\
	return z != 0;			\
}

#define PCODE_BIOP_ADDUNUSED(typ)		\
typ typ##_additionUnused(UNUSED typ val,		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs + rhs;			\
	return z;			\
}\
typ typ##_additionUnusedImm(UNUSED typ val,		\
			    typ lhs)			\
{					\
	typ z;				\
	z = lhs + 5;			\
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

#define PCODE_BIOP_ADDNEGONE(typ)      	\
typ typ##_additionNegOne(      		\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 + val;	       	\
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
}\
typ typ##_bitwiseAndImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs & 5;			\
	return z;			\
}

#define PCODE_BIOP_ANDEQZero(typ)      	\
typ typ##_bitwiseAndEQZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z == 0;			\
}\
typ typ##_bitwiseAndEQZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs & 5;			\
	return z == 0;			\
}

#define PCODE_BIOP_ANDNEZero(typ)      	\
typ typ##_bitwiseAndNEZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z != 0;			\
}\
typ typ##_bitwiseAndNEZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs & 5;			\
	return z != 0;			\
}

#define PCODE_BIOP_ANDEQNegOne(typ)     \
typ typ##_bitwiseAndEQNegOne(    	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z == (typ)-1;   		\
}

#define PCODE_BIOP_ANDNENegOne(typ)     \
typ typ##_bitwiseAndNENegOne(    	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z != (typ)-1;	       	\
}

#define PCODE_BIOP_ANDEQ(typ)		\
typ typ##_bitwiseAndEQ(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z == lhs;       		\
}\
typ typ##_bitwiseAndEQImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs & 5;			\
	return z == lhs;       		\
}

#define PCODE_BIOP_ANDNE(typ)		\
typ typ##_bitwiseAndNE(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z != lhs;	       	\
}\
typ typ##_bitwiseAndNEImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs & 5;			\
	return z != lhs;	       	\
}

#define PCODE_BIOP_ANDUNUSED(typ)		\
typ typ##_bitwiseAndUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs & rhs;			\
	return z;			\
}\
typ typ##_bitwiseAndUnusedImm(UNUSED typ val,	\
			      typ lhs)		\
{					\
	typ z;				\
	z = lhs & 5;			\
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

#define PCODE_BIOP_ANDNEGONE(typ)		\
typ typ##_bitwiseAndNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 & val;			\
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
}\
typ typ##_bitwiseOrImm(			\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs | 5;			\
	return z;			\
}

#define PCODE_BIOP_OREQZero(typ)       	\
typ typ##_bitwiseOrEQZero(     		\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z == 0;			\
}

#define PCODE_BIOP_ORNEZero(typ)       	\
typ typ##_bitwiseOrNEZero(     		\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z != 0;			\
}

#define PCODE_BIOP_OREQNegOne(typ)       	\
typ typ##_bitwiseOrEQNegOne(     		\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z == (typ)-1;			\
}\
typ typ##_bitwiseOrEQNegOneImm(     		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs | 5;			\
	return z == (typ)-1;			\
}

#define PCODE_BIOP_ORNENegOne(typ)       	\
typ typ##_bitwiseOrNENegOne(     		\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z != (typ)-1;			\
}\
typ typ##_bitwiseOrNENegOneImm(     		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs | 5;			\
	return z != (typ)-1;			\
}

#define PCODE_BIOP_OREQ(typ)		\
typ typ##_bitwiseOrEQ(			\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z == lhs;	       	\
}\
typ typ##_bitwiseOrEQImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs | 5;			\
	return z == lhs;	       	\
}

#define PCODE_BIOP_ORNE(typ)		\
typ typ##_bitwiseOrNE(			\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z != lhs;       		\
}\
typ typ##_bitwiseOrNEImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs | 5;			\
	return z != lhs;       		\
}

#define PCODE_BIOP_ORUNUSED(typ)		\
typ typ##_bitwiseOrUnused(UNUSED typ val,	\
			 typ lhs,	\
			 typ rhs)	\
{					\
	typ z;				\
	z = lhs | rhs;			\
	return z;			\
}\
typ typ##_bitwiseOrUnusedImm(UNUSED typ val,	\
			  typ lhs)		\
{					\
	typ z;				\
	z = lhs | 5;			\
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

#define PCODE_BIOP_ORNEGONE(typ)		\
typ typ##_bitwiseOrNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 | val;			\
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
}\
typ typ##_bitwiseXorImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z;			\
}

#define PCODE_BIOP_XOREQZero(typ)      	\
typ typ##_bitwiseXorEQZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z == 0;			\
}\
typ typ##_bitwiseXorEQZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z == 0;			\
}

#define PCODE_BIOP_XORNEZero(typ)      	\
typ typ##_bitwiseXorNEZero(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z != 0;			\
}\
typ typ##_bitwiseXorNEZeroImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z != 0;			\
}

#define PCODE_BIOP_XOREQNegOne(typ)      	\
typ typ##_bitwiseXorEQNegOne(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z == (typ)-1;			\
}\
typ typ##_bitwiseXorEQNegOneImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z == (typ)-1;			\
}

#define PCODE_BIOP_XORNENegOne(typ)      	\
typ typ##_bitwiseXorNENegOne(    		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z != (typ)-1;			\
}\
typ typ##_bitwiseXorNENegOneImm(    		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z != (typ)-1;			\
}

#define PCODE_BIOP_XOREQ(typ)		\
typ typ##_bitwiseXorEQ(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z == lhs;	       	\
}\
typ typ##_bitwiseXorEQImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z == lhs;	       	\
}

#define PCODE_BIOP_XORNE(typ)		\
typ typ##_bitwiseXorNE(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z != lhs;	       	\
}\
typ typ##_bitwiseXorNEImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z != lhs;	       	\
}

#define PCODE_BIOP_XORUNUSED(typ)		\
typ typ##_bitwiseXorUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs ^ rhs;			\
	return z;			\
}\
typ typ##_bitwiseXorUnusedImm(UNUSED typ val,	\
			      typ lhs)		\
{					\
	typ z;				\
	z = lhs ^ 5;			\
	return z;			\
}

#define PCODE_BIOP_XORZERO(typ)		\
typ typ##_bitwiseXorZero(			\
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

#define PCODE_BIOP_XORNEGONE(typ)		\
typ typ##_bitwiseXorNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 ^ val;			\
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
}\
typ typ##_shiftLeftImm(			\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs << 5;		\
	return z;			\
}

#define PCODE_BIOP_SHLEQZero(typ)      	\
typ typ##_shiftLeftEQZero(     		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z == 0;			\
}\
typ typ##_shiftLeftEQZeroImm(     		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs << 5;		\
	return z == 0;			\
}

#define PCODE_BIOP_SHLNEZero(typ)      	\
typ typ##_shiftLeftNEZero(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z != 0;			\
}\
typ typ##_shiftLeftNEZeroImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs << 5;		\
	return z != 0;			\
}

#define PCODE_BIOP_SHLEQNegOne(typ)      	\
typ typ##_shiftLeftEQNegOne(     		\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z == (typ)-1;		\
}\
typ typ##_shiftLeftEQNegImm(     		\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs << 5;		\
	return z == (typ)-1;		\
}

#define PCODE_BIOP_SHLNENegOne(typ)      	\
typ typ##_shiftLeftNENegOne(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z != (typ)-1;		\
}\
typ typ##_shiftLeftNENegOneImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs << 5;		\
	return z != (typ)-1;		\
}

#define PCODE_BIOP_SHLUNUSED(typ)		\
typ typ##_shiftLeftUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs << rhs;		\
	return z;			\
}\
typ typ##_shiftLeftUnusedImm(UNUSED typ val,	\
			     typ lhs)		\
{					\
	typ z;				\
	z = lhs << 5;		\
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
}\
typ typ##_shiftRightImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs >> 5;		\
	return z;			\
}

#define PCODE_BIOP_SHREQZero(typ)      	\
typ typ##_shiftRightEQZero(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z == 0;			\
}\
typ typ##_shiftRightEQZeroImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs >> 5;		\
	return z == 0;			\
}

#define PCODE_BIOP_SHRNEZero(typ)      	\
typ typ##_shiftRightNEZero(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z != 0;			\
}\
typ typ##_shiftRightNEZeroImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs >> 5;		\
	return z != 0;			\
}

#define PCODE_BIOP_SHREQNegOne(typ)      	\
typ typ##_shiftRightEQNegOne(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z == (typ)-1;		\
}\
typ typ##_shiftRightEQNegOneImm(	       	\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs >> 5;		\
	return z == (typ)-1;		\
}

#define PCODE_BIOP_SHRNENegOne(typ)      	\
typ typ##_shiftRightNENegOne(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z != (typ)-1;		\
}\
typ typ##_shiftRightNENegOneImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs >> 5;		\
	return z != (typ)-1;		\
}

#define PCODE_BIOP_SHRUNUSED(typ)		\
typ typ##_shiftRightUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs >> rhs;		\
	return z;			\
}\
typ typ##_shiftRightUnusedImm(UNUSED typ val,	\
			      typ lhs)		\
{					\
	typ z;				\
	z = lhs >> 5;		\
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
}\
typ typ##_divideImm(			\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs / 5;			\
	return z;			\
}

#define PCODE_BIOP_DIVEQZero(typ)		\
typ typ##_divideEqZero(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs / rhs;			\
	return z == 0;			\
}\
typ typ##_divideEqZeroImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs / 5;			\
	return z == 0;			\
}

#define PCODE_BIOP_DIVNEZero(typ)		\
typ typ##_divideNeZero(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs / rhs;			\
	return z != 0;			\
}\
typ typ##_divideNeZeroImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs / 5;			\
	return z != 0;			\
}

#define PCODE_BIOP_DIVUNUSED(typ)		\
typ typ##_divideUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs / rhs;			\
	return z;			\
}\
typ typ##_divideUnusedImm(UNUSED typ val,	\
			  typ lhs)		\
{					\
	typ z;				\
	z = lhs / 5;			\
	return z;			\
}

#define PCODE_BIOP_DIVZERO(typ)		\
typ typ##_divideZero(			\
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

#define PCODE_BIOP_DIVNEGONE(typ)		\
typ typ##_divideNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 / val;			\
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

#define PCODE_BIOP_REMNEGONE(typ)		\
typ typ##_remainderNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 % val;			\
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
}\
typ typ##_multiplyImm(			\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs * 5;			\
	return z;			\
}

#define PCODE_BIOP_MULEQZero(typ)		\
typ typ##_multiplyEqZero(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z == 0;			\
}\
typ typ##_multiplyEqZeroImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs * 5;			\
	return z == 0;			\
}

#define PCODE_BIOP_MULNEZero(typ)		\
typ typ##_multiplyNeZero(			\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z != 0;			\
}\
typ typ##_multiplyNeZeroImm(			\
						typ lhs)	\
{					\
	typ z;				\
	z = lhs * 5;			\
	return z != 0;			\
}

#define PCODE_BIOP_MUL_OV(typ)		\
typ typ##_multiplyOverflow(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z < lhs || z < rhs;     	\
}\
typ typ##_multiplyOverflowImm(	       	\
					typ lhs)	\
{					\
	typ z;				\
	z = lhs * 5;			\
	return z < lhs || z < 5;     	\
}

#define PCODE_BIOP_MUL_NOOV(typ)		\
typ typ##_multiplyNoOverflow(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z >= lhs;     	\
}\
typ typ##_multiplyNoOverflowImm(	       	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * 5;			\
	return z >= lhs;     	\
}

#define PCODE_BIOP_MULUNUSED(typ)		\
typ typ##_multiplyUnused(UNUSED typ val,	\
			typ lhs,	\
			typ rhs)	\
{					\
	typ z;				\
	z = lhs * rhs;			\
	return z;			\
}\
typ typ##_multiplyUnusedImm(UNUSED typ val,	\
			    typ lhs)		\
{					\
	typ z;				\
	z = lhs * 5;			\
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

#define PCODE_BIOP_MULNEGONE(typ)		\
typ typ##_multiplyNegOne(			\
			typ val)	\
{					\
	typ z;				\
	z = (typ)-1 * val;			\
	return z;			\
}


#define PCODE_BIOPS(typ)			\
	PCODE_BIOP_ADD(typ)			\
	PCODE_BIOP_ADD_OV(typ)			\
	PCODE_BIOP_ADD_NOOV(typ)			\
	PCODE_BIOP_ADDEQZero(typ)      		\
	PCODE_BIOP_ADDNEZero(typ)	       	\
	PCODE_BIOP_ADDUNUSED(typ)		\
	PCODE_BIOP_ADDZERO(typ)			\
	PCODE_BIOP_ADDONE(typ)			\
	PCODE_BIOP_ADDNEGONE(typ)      		\
	PCODE_BIOP_AND(typ)			\
	PCODE_BIOP_ANDEQZero(typ)      		\
	PCODE_BIOP_ANDNEZero(typ)      		\
	PCODE_BIOP_ANDEQNegOne(typ)      	\
	PCODE_BIOP_ANDNENegOne(typ)      	\
	PCODE_BIOP_ANDEQ(typ)			\
	PCODE_BIOP_ANDNE(typ)			\
	PCODE_BIOP_ANDUNUSED(typ)		\
	PCODE_BIOP_ANDZERO(typ)			\
	PCODE_BIOP_ANDONE(typ)			\
	PCODE_BIOP_ANDNEGONE(typ)			\
	PCODE_BIOP_OR(typ)			\
	PCODE_BIOP_OREQZero(typ)       		\
	PCODE_BIOP_ORNEZero(typ)     		\
	PCODE_BIOP_OREQNegOne(typ)       		\
	PCODE_BIOP_ORNENegOne(typ)     		\
	PCODE_BIOP_OREQ(typ)			\
	PCODE_BIOP_ORNE(typ)			\
	PCODE_BIOP_ORUNUSED(typ)		\
	PCODE_BIOP_ORZERO(typ)			\
	PCODE_BIOP_ORONE(typ)			\
	PCODE_BIOP_ORNEGONE(typ)			\
	PCODE_BIOP_SHL(typ)			\
	PCODE_BIOP_SHLEQZero(typ)      		\
	PCODE_BIOP_SHLNEZero(typ)      		\
	PCODE_BIOP_SHLEQNegOne(typ)      		\
	PCODE_BIOP_SHLNENegOne(typ)      		\
	PCODE_BIOP_SHLUNUSED(typ)		\
	PCODE_BIOP_SHLZERO(typ)			\
	PCODE_BIOP_SHLONE(typ)			\
	PCODE_BIOP_SHR(typ)			\
	PCODE_BIOP_SHREQZero(typ)      		\
	PCODE_BIOP_SHRNEZero(typ)	       	\
	PCODE_BIOP_SHREQNegOne(typ)      		\
	PCODE_BIOP_SHRNENegOne(typ)	       	\
	PCODE_BIOP_SHRUNUSED(typ)		\
	PCODE_BIOP_SHRZERO(typ)			\
	PCODE_BIOP_SHRONE(typ)			\
	PCODE_BIOP_SUB(typ)			\
	PCODE_BIOP_SUBEQZero(typ)      		\
	PCODE_BIOP_SUBNEZero(typ)      		\
	PCODE_BIOP_SUB_UF(typ)			\
	PCODE_BIOP_SUBUNUSED(typ)		\
	PCODE_BIOP_SUBZERO(typ)			\
	PCODE_BIOP_SUBONE(typ)			\
	PCODE_BIOP_SUBNEGONE(typ)      		\
	PCODE_BIOP_XOR(typ)			\
	PCODE_BIOP_XOREQZero(typ)      		\
	PCODE_BIOP_XORNEZero(typ)      		\
	PCODE_BIOP_XOREQNegOne(typ)      		\
	PCODE_BIOP_XORNENegOne(typ)      		\
	PCODE_BIOP_XOREQ(typ)			\
	PCODE_BIOP_XORNE(typ)			\
	PCODE_BIOP_XORUNUSED(typ)		\
	PCODE_BIOP_XORZERO(typ)			\
	PCODE_BIOP_XORONE(typ)			\
	PCODE_BIOP_XORNEGONE(typ)			\
	PCODE_COMPLEX_LOGIC(typ)		\
	PCODE_BIOP_LOGIC_OR(typ)		\
	PCODE_BIOP_LOGIC_ORUNUSED(typ)		\
	PCODE_BIOP_LOGIC_AND(typ)		\
	PCODE_BIOP_LOGIC_ANDUNUSED(typ)		\
	PCODE_BIOP_MUL(typ)			\
	PCODE_BIOP_MULEQZero(typ)      		\
	PCODE_BIOP_MULNEZero(typ)	       	\
	PCODE_BIOP_MUL_OV(typ)			\
	PCODE_BIOP_MUL_NOOV(typ)			\
	PCODE_BIOP_MULUNUSED(typ)		\
	PCODE_BIOP_MULZERO(typ)			\
	PCODE_BIOP_MULONE(typ)			\
	PCODE_BIOP_MULNEGONE(typ)			\
	PCODE_BIOP_DIV(typ)			\
	PCODE_BIOP_DIVEQZero(typ)	       	\
	PCODE_BIOP_DIVNEZero(typ)	       	\
	PCODE_BIOP_DIVUNUSED(typ)		\
	PCODE_BIOP_DIVZERO(typ)			\
	PCODE_BIOP_DIVONE(typ)			\
	PCODE_BIOP_DIVNEGONE(typ)			\
	PCODE_BIOP_REM(typ)			\
	PCODE_BIOP_REMUNUSED(typ)		\
	PCODE_BIOP_REMZERO(typ)			\
	PCODE_BIOP_REMONE(typ)			\
	PCODE_BIOP_REMNEGONE(typ)


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
