package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSitJournalEntryHeader implements StructConverter {
	
	public static final String NAME = "sit_journal_entry";
	
	private long start_index;
	private long end_index;
	
	private long segno;
	private F2FSSitEntryHeader se;

	public F2FSSitJournalEntryHeader() {
	}
	
	public F2FSSitJournalEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		segno = reader.readNextUnsignedInt();
		se = new F2FSSitEntryHeader(reader);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x4e;
	}
	
	public long getSegno() {
		return segno;
	}
	
	public F2FSSitEntryHeader getSe() {
		return se;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "segno", null);
		structure.add(new F2FSSitEntryHeader().toDataType(), "se", null);	

		return structure;
	}

}
