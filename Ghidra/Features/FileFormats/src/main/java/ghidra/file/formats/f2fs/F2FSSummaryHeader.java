package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSummaryHeader implements StructConverter {
	
	public static final String NAME = "f2fs_summary";

	private long start_index;
	private long end_index;
	
	private long nid;
	private int version;
	private int ofs_in_mode;

	public F2FSSummaryHeader() {
	}

	public F2FSSummaryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		nid = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedByte();
		ofs_in_mode = reader.readNextUnsignedShort();
		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.SUMMARY_SIZE;
		//dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSSummaryHeader (s=0x%x, e=0x%x) nid=%d, version=%d, ofs_in_mode=%d",
				start_index, end_index, nid, version, ofs_in_mode));
	}

	public long getNid() {
		return nid;
	}
	
	public int getVersion() {
		return version;
	}
	
	public int getOfsInMode() {
		return ofs_in_mode;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "nid", null);
		structure.add(BYTE, "version", null);
		structure.add(WORD, "ofs_in_node", null);
		
		return structure;
	}

}
