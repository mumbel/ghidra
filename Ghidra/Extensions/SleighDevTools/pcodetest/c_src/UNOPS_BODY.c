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


#define PCODE_UNOP_INCPRE(typ)			\
  typ unopIncPre##typ(typ lhs) {	       	\
    typ z;					\
    z = ++lhs;					\
    return z;					\
  }

#define PCODE_UNOP_INCPOST(typ)			\
  typ unopIncPost##typ(typ lhs) {	       	\
    typ z;					\
    z = lhs++;       				\
    return z;					\
  }

#define PCODE_UNOP_DECPRE(typ)			\
  typ unopDecPre##typ(typ lhs) {	       	\
    typ z;					\
    z = --lhs;					\
    return z;					\
  }

#define PCODE_UNOP_DECPOST(typ)			\
  typ unopDecPost##typ(typ lhs) {	       	\
    typ z;					\
    z = lhs--;       				\
    return z;					\
  }

#define PCODE_UNOP_INDIRECT(typ)	       	\
  typ unopIndirect##typ(typ *lhs) {	       	\
    typ z;					\
    z = *lhs;       				\
    return z;					\
  }

#define PCODE_UNOP_POS(typ)			\
  typ unopPositive##typ(typ lhs) {	       	\
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

#define PCODE_UNOP_ONESCOMP(typ)	       	\
  typ unopOnesComp##typ(typ lhs) {	       	\
    typ z;					\
    z = ~lhs;					\
    return z;					\
  }

#define PCODE_UNOP_LOGNEG(typ)			\
  typ unopLogicalNegate##typ(typ lhs) {	       	\
    typ z;					\
    z = !lhs;					\
    return z;					\
  }

PCODE_UNOP_INCPRE(i1);
PCODE_UNOP_INCPRE(u1);
PCODE_UNOP_INCPRE(i2);
PCODE_UNOP_INCPRE(u2);
PCODE_UNOP_INCPRE(i4);
PCODE_UNOP_INCPRE(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_INCPRE(i8);
PCODE_UNOP_INCPRE(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_INCPRE(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_INCPRE(f8);
#endif

PCODE_UNOP_INCPOST(i1);
PCODE_UNOP_INCPOST(u1);
PCODE_UNOP_INCPOST(i2);
PCODE_UNOP_INCPOST(u2);
PCODE_UNOP_INCPOST(i4);
PCODE_UNOP_INCPOST(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_INCPOST(i8);
PCODE_UNOP_INCPOST(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_INCPOST(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_INCPOST(f8);
#endif

PCODE_UNOP_DECPRE(i1);
PCODE_UNOP_DECPRE(u1);
PCODE_UNOP_DECPRE(i2);
PCODE_UNOP_DECPRE(u2);
PCODE_UNOP_DECPRE(i4);
PCODE_UNOP_DECPRE(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_DECPRE(i8);
PCODE_UNOP_DECPRE(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_DECPRE(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_DECPRE(f8);
#endif

PCODE_UNOP_DECPOST(i1);
PCODE_UNOP_DECPOST(u1);
PCODE_UNOP_DECPOST(i2);
PCODE_UNOP_DECPOST(u2);
PCODE_UNOP_DECPOST(i4);
PCODE_UNOP_DECPOST(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_DECPOST(i8);
PCODE_UNOP_DECPOST(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_DECPOST(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_DECPOST(f8);
#endif

PCODE_UNOP_INDIRECT(i1);
PCODE_UNOP_INDIRECT(u1);
PCODE_UNOP_INDIRECT(i2);
PCODE_UNOP_INDIRECT(u2);
PCODE_UNOP_INDIRECT(i4);
PCODE_UNOP_INDIRECT(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_INDIRECT(i8);
PCODE_UNOP_INDIRECT(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_INDIRECT(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_INDIRECT(f8);
#endif

PCODE_UNOP_POS(i1);
PCODE_UNOP_POS(u1);
PCODE_UNOP_POS(i2);
PCODE_UNOP_POS(u2);
PCODE_UNOP_POS(i4);
PCODE_UNOP_POS(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_POS(i8);
PCODE_UNOP_POS(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_POS(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_POS(f8);
#endif

PCODE_UNOP_NEG(i1);
PCODE_UNOP_NEG(u1);
PCODE_UNOP_NEG(i2);
PCODE_UNOP_NEG(u2);
PCODE_UNOP_NEG(i4);
PCODE_UNOP_NEG(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_NEG(i8);
PCODE_UNOP_NEG(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_NEG(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_NEG(f8);
#endif

PCODE_UNOP_ONESCOMP(i1);
PCODE_UNOP_ONESCOMP(u1);
PCODE_UNOP_ONESCOMP(i2);
PCODE_UNOP_ONESCOMP(u2);
PCODE_UNOP_ONESCOMP(i4);
PCODE_UNOP_ONESCOMP(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_ONESCOMP(i8);
PCODE_UNOP_ONESCOMP(u8);
#endif
//#ifdef HAS_FLOAT
//PCODE_UNOP_ONESCOMP(f4);
//#endif
//#ifdef HAS_DOUBLE
//PCODE_UNOP_ONESCOMP(f8);
//#endif

PCODE_UNOP_LOGNEG(i1);
PCODE_UNOP_LOGNEG(u1);
PCODE_UNOP_LOGNEG(i2);
PCODE_UNOP_LOGNEG(u2);
PCODE_UNOP_LOGNEG(i4);
PCODE_UNOP_LOGNEG(u4);
#ifdef HAS_LONGLONG
PCODE_UNOP_LOGNEG(i8);
PCODE_UNOP_LOGNEG(u8);
#endif
#ifdef HAS_FLOAT
PCODE_UNOP_LOGNEG(f4);
#endif
#ifdef HAS_DOUBLE
PCODE_UNOP_LOGNEG(f8);
#endif
