package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNatBlockHeader implements StructConverter {

	public static final String NAME = "f2fs_nat_block";
	
	private long start_index;
	private long end_index;
	
	private F2FSNatEntryHeader[] entries;
	
	public F2FSNatBlockHeader() {
	}
	
	public F2FSNatBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entries = new F2FSNatEntryHeader[F2FSConstants.NAT_ENTRY_PER_BLOCK];
		for (int i = 0; i < F2FSConstants.NAT_ENTRY_PER_BLOCK; i++) {
			entries[i] = new F2FSNatEntryHeader(reader);
		}
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xfff;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSNatBlockHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public F2FSNatEntryHeader[] getEntries() {
		return entries;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		DataType entry = new F2FSNatEntryHeader().toDataType();
		structure.add(new ArrayDataType(entry, F2FSConstants.NAT_ENTRY_PER_BLOCK, entry.getLength()), "entries", null);

		return structure;
	}

}
