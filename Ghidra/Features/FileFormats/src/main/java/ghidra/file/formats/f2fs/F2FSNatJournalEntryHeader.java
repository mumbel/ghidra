package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNatJournalEntryHeader implements StructConverter {
	
	public static final String NAME = "nat_journal_entry";
	
	private long start_index;
	private long end_index;

	private long nid;
	private F2FSNatEntryHeader ne;
	
	public F2FSNatJournalEntryHeader() {
	}
	
	public F2FSNatJournalEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		nid = reader.readNextUnsignedInt();
		ne = new F2FSNatEntryHeader(reader);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xd;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSNatJournalEntryHeader (s=0x%x, e=0x%x) nid %d",
				start_index, end_index, nid));
	}
	
	public long getNid() {
		return nid;
	}
	
	public F2FSNatEntryHeader getNe() {
		return ne;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "nid", null);
		structure.add(new F2FSNatEntryHeader().toDataType(), "ne", null);	

		return structure;
	}

}
