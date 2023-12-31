package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSummaryFooterHeader implements StructConverter {
	
	public static final String NAME = "summary_footer";

	private long start_index;
	private long end_index;

	private int entry_type;
	private long check_sum;
	
	public F2FSSummaryFooterHeader() {
	}
	
	public F2FSSummaryFooterHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		entry_type = reader.readNextUnsignedByte();
		check_sum = reader.readNextUnsignedInt();
		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.SUM_FOOTER_SIZE;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSSummaryFooterHeader (s=0x%x, e=0x%x) type=0x%x, sum=0x%x",
				start_index, end_index, entry_type, check_sum));
	}
	
	public int getEntryType() {
		return entry_type;
	}
	
	public long getCheckSum() {
		return check_sum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(BYTE, "entry_type", null);
		structure.add(DWORD, "check_sum", null);
		
		return structure;
	}

}
