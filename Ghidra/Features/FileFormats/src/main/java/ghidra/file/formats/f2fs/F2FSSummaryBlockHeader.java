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

public class F2FSSummaryBlockHeader implements StructConverter {
	
	public static final String NAME = "f2fs_summary_block";
	
	private long start_index;
	private long end_index;
	
	private F2FSSummaryHeader[] entries;
	private F2FSJournalHeader journal;
	private F2FSSummaryFooterHeader footer;
	
	public F2FSSummaryBlockHeader() {
	}
	
	public F2FSSummaryBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entries = new F2FSSummaryHeader[F2FSConstants.ENTRIES_IN_SUM];
		for (int i = 0; i < F2FSConstants.ENTRIES_IN_SUM; i++) {
			entries[i] = new F2FSSummaryHeader(reader);
		}
		journal = new F2FSJournalHeader(reader, F2FSConstants.F2FSJournalType.SIT_JOURNAL);
		footer = new F2FSSummaryFooterHeader(reader);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.F2FS_BLKSIZE;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSSummaryBlockHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public F2FSSummaryHeader[] getEntries() {
		return entries;
	}
	
	public F2FSJournalHeader getJournal() {
		return journal;
	}
	
	public F2FSSummaryFooterHeader getFooter() {
		return footer;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		DataType entry = new F2FSSummaryHeader().toDataType();
		structure.add(new ArrayDataType(entry, F2FSConstants.ENTRIES_IN_SUM, entry.getLength()), "entries", null);
		structure.add(new F2FSJournalHeader().toDataType(), "journal", null);
		structure.add(new F2FSSummaryFooterHeader().toDataType(), "footer", null);

		return structure;
	}

}
