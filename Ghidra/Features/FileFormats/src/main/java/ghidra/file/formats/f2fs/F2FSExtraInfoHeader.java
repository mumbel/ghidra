package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSExtraInfoHeader implements StructConverter {
	
	public static final String NAME = "f2fs_extra_info"; 
	
	private long start_index;
	private long end_index;

	private long kbytes_written; //TODO
	private byte[] reserved; //TODO

	public F2FSExtraInfoHeader() {
	}
	
	public F2FSExtraInfoHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		kbytes_written = reader.readNextLong();
		reserved = reader.readNextByteArray(F2FSConstants.EXTRA_INFO_RESERVED);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x1f9;
	}
	
	public long getKbytesWritten() {
		return kbytes_written;
	}
	
	public byte[] getReserved() {
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(QWORD, "kbytes_written", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.EXTRA_INFO_RESERVED, BYTE.getLength()), "reserved", null);
		
		return structure;
	}

}
