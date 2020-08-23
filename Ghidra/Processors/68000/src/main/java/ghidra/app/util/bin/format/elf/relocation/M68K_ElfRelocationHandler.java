package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class M68K_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_68K;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {
		// TODO Auto-generated method stub
		final int type = relocation.getType();
		if (M68K_ElfRelocationConstants.R_68K_NONE == type) {
			return;
		}
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		
		final int symbolIndex = relocation.getSymbolIndex();
		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();
		final long symbolValue = elfRelocationContext.getSymbolValue(sym);
		final long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		final long addend = relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);
		final long offset = relocationAddress.getOffset();
		int value = 0;
		
		switch (type) {
		default:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "UNKNOWN " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_32:
			/* Direct 32 bit  */
			value = (int)(symbolValue + addend);
			memory.setInt(relocationAddress, value);
			break;
		case M68K_ElfRelocationConstants.R_68K_16:
			/* Direct 16 bit  */
			value = (int)(symbolValue + addend);
			memory.setShort(relocationAddress, (short)value);
			break;
		case M68K_ElfRelocationConstants.R_68K_8:
			/* Direct 8 bit  */
			value = (int)(symbolValue + addend);
			memory.setByte(relocationAddress, (byte)value);
			break;
		case M68K_ElfRelocationConstants.R_68K_PC32:
			/* PC relative 32 bit */
			value = (int)(symbolValue + addend - offset);
			memory.setInt(relocationAddress, value);
			break;
		case M68K_ElfRelocationConstants.R_68K_PC16:
			/* PC relative 16 bit */
			value = (int)(symbolValue + addend - offset);
			memory.setShort(relocationAddress, (short)value);
			break;
		case M68K_ElfRelocationConstants.R_68K_PC8:
			/* PC relative 8 bit */
			value = (int)(symbolValue + addend - offset);
			memory.setByte(relocationAddress, (byte)value);
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT32O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT16O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GOT8O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT32O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT16O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_PLT8O:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_COPY:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GLOB_DAT:
			/* Create GOT entry */
			value = (int)(symbolValue + addend);
			memory.setInt(relocationAddress, value);
			break;
		case M68K_ElfRelocationConstants.R_68K_JMP_SLOT:
			/* Create PLT entry */
			value = (int)symbolValue;
			memory.setInt(relocationAddress, value);
			break;
		case M68K_ElfRelocationConstants.R_68K_RELATIVE:
			/* Adjust by program base */
			value = (int)(base + addend);
			memory.setInt(relocationAddress, value);
			break;
		case M68K_ElfRelocationConstants.R_68K_GNU_VTINHERIT:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_GNU_VTENTRY:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_GD32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_GD16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_GD8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDM32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDM16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDM8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDO32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDO16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LDO8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_IE32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_IE16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_IE8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LE32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LE16:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_LE8:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_DTPMOD32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_DTPREL32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		case M68K_ElfRelocationConstants.R_68K_TLS_TPREL32:
			markAsWarning(program, relocationAddress, "type " + type, symbolName, symbolIndex, "TODO " + type, elfRelocationContext.getLog());
			break;
		}
	}

}
