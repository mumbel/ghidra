/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License = Version 2.0 (the "License";;
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing = software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND = either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

public class M68K_ElfRelocationConstants {
	  public static final int R_68K_NONE = 0;		/* No reloc */
	  public static final int R_68K_32 = 1;		/* Direct 32 bit  */
	  public static final int R_68K_16 = 2;		/* Direct 16 bit  */
	  public static final int R_68K_8 = 3;		/* Direct 8 bit  */
	  public static final int R_68K_PC32 = 4;		/* PC relative 32 bit */
	  public static final int R_68K_PC16 = 5;		/* PC relative 16 bit */
	  public static final int R_68K_PC8 = 6;		/* PC relative 8 bit */
	  public static final int R_68K_GOT32 = 7;		/* 32 bit PC relative GOT entry */
	  public static final int R_68K_GOT16 = 8;		/* 16 bit PC relative GOT entry */
	  public static final int R_68K_GOT8 = 9;		/* 8 bit PC relative GOT entry */
	  public static final int R_68K_GOT32O = 10;	/* 32 bit GOT offset */
	  public static final int R_68K_GOT16O = 11;	/* 16 bit GOT offset */
	  public static final int R_68K_GOT8O = 12;	/* 8 bit GOT offset */
	  public static final int R_68K_PLT32 = 13;	/* 32 bit PC relative PLT address */
	  public static final int R_68K_PLT16 = 14;	/* 16 bit PC relative PLT address */
	  public static final int R_68K_PLT8 = 15;		/* 8 bit PC relative PLT address */
	  public static final int R_68K_PLT32O = 16;	/* 32 bit PLT offset */
	  public static final int R_68K_PLT16O = 17;	/* 16 bit PLT offset */
	  public static final int R_68K_PLT8O = 18;	/* 8 bit PLT offset */
	  public static final int R_68K_COPY = 19;		/* Copy symbol at runtime */
	  public static final int R_68K_GLOB_DAT = 20;	/* Create GOT entry */
	  public static final int R_68K_JMP_SLOT = 21;	/* Create PLT entry */
	  public static final int R_68K_RELATIVE = 22;	/* Adjust by program base */
	  /* These are GNU extensions to enable C++ vtable garbage collection.  */
	  public static final int R_68K_GNU_VTINHERIT = 23;
	  public static final int R_68K_GNU_VTENTRY = 24;
	  /* TLS static relocations.  */
	  public static final int R_68K_TLS_GD32 = 25;
	  public static final int R_68K_TLS_GD16 = 26;
	  public static final int R_68K_TLS_GD8 = 27;
	  public static final int R_68K_TLS_LDM32 = 28;
	  public static final int R_68K_TLS_LDM16 = 29;
	  public static final int R_68K_TLS_LDM8 = 30;
	  public static final int R_68K_TLS_LDO32 = 31;
	  public static final int R_68K_TLS_LDO16 = 32;
	  public static final int R_68K_TLS_LDO8 = 33;
	  public static final int R_68K_TLS_IE32 = 34;
	  public static final int R_68K_TLS_IE16 = 35;
	  public static final int R_68K_TLS_IE8 = 36;
	  public static final int R_68K_TLS_LE32 = 37;
	  public static final int R_68K_TLS_LE16 = 38;
	  public static final int R_68K_TLS_LE8 = 39;
	  public static final int R_68K_TLS_DTPMOD32 = 40;
	  public static final int R_68K_TLS_DTPREL32 = 41;
	  public static final int R_68K_TLS_TPREL32 = 42;
}
