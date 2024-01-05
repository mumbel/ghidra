package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNatJournalHeader implements StructConverter {
	
	public static final String NAME = "nat_journal";
	
	private long start_index;
	private long end_index;
	
	private F2FSNatJournalEntryHeader[] entries;
	private byte[] reserved;

	public F2FSNatJournalHeader() {
	}
	
	public F2FSNatJournalHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entries = new F2FSNatJournalEntryHeader[F2FSConstants.NAT_JOURNAL_ENTRIES];
		for (int i = 0; i < F2FSConstants.NAT_JOURNAL_ENTRIES; i++) {
			entries[i] = new F2FSNatJournalEntryHeader(reader);
		}
		reserved = reader.readNextByteArray(F2FSConstants.NAT_JOURNAL_RESERVED);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x1f9;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSNatJournalHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public F2FSNatJournalEntryHeader[] getEntries() {
		return entries;
	}
	
	public byte[] getReserved() {
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		DataType entry = new F2FSNatJournalEntryHeader().toDataType();
		
		structure.add(new ArrayDataType(entry, F2FSConstants.NAT_JOURNAL_ENTRIES, entry.getLength()), "entries", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.NAT_JOURNAL_RESERVED, BYTE.getLength()), "reserved", null);

		return structure;
	}

}
