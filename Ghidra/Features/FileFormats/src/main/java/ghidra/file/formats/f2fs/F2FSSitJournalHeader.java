package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSitJournalHeader implements StructConverter {
	
	public static final String NAME = "sit_journal";
	
	private long start_index;
	private long end_index;

	private F2FSSitJournalEntryHeader[] entries;
	private byte[] reserved;

	public F2FSSitJournalHeader() {
	}
	
	public F2FSSitJournalHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entries = new F2FSSitJournalEntryHeader[F2FSConstants.SIT_JOURNAL_ENTRIES];
		for (int i = 0; i < F2FSConstants.SIT_JOURNAL_ENTRIES; i++) {
			entries[i] = new F2FSSitJournalEntryHeader(reader);
		}
		reserved = reader.readNextByteArray(F2FSConstants.SIT_JOURNAL_RESERVED);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x1f9;
	}
	
	public F2FSSitJournalEntryHeader[] getEntries() {
		return entries;
	}
	
	public byte[] getReserved() {
		return reserved;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		DataType entry = new F2FSSitJournalEntryHeader().toDataType();
		
		structure.add(new ArrayDataType(entry, F2FSConstants.SIT_JOURNAL_ENTRIES, entry.getLength()), "entries", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.SIT_JOURNAL_RESERVED, BYTE.getLength()), "reserved", null);

		return structure;
	}

}
