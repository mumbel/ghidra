package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSitBlockHeader implements StructConverter {
	
	public static final String NAME = "f2fs_sit_block";
	
	private long start_index;
	private long end_index;
	
	private F2FSSitEntryHeader[] entries;
	
	public F2FSSitBlockHeader() {
	}
	
	public F2FSSitBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entries = new F2FSSitEntryHeader[F2FSConstants.SIT_ENTRY_PER_BLOCK];
		for (int i = 0; i < F2FSConstants.SIT_ENTRY_PER_BLOCK; i++) {
			entries[i] = new F2FSSitEntryHeader(reader);
		}
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xfe6;
	}
	
	public F2FSSitEntryHeader[] getEntries() {
		return entries;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		DataType entry = new F2FSSitEntryHeader().toDataType();
		structure.add(new ArrayDataType(entry, 4096 / entry.getLength(), entry.getLength()), "entries", null);

		return structure;
	}

}
