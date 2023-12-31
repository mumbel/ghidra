package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSXattrEntryHeader implements StructConverter {

	public static final String NAME = "f2fs_xattr_header";
	
	private long start_index;
	private long end_index;

	private int e_name_index;
	private int e_name_len;
	private int e_value_size;
	private byte[] e_name;
	
	public F2FSXattrEntryHeader() {
	}
	
	public F2FSXattrEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		e_name_index = reader.readNextUnsignedByte();
		e_name_len = reader.readNextUnsignedByte();
		e_value_size = reader.readNextUnsignedShort();
		//TODO  some validation on e_name_len?
		e_name = reader.readNextByteArray(e_name_len);
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 4 + e_name_len;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSXattrEntryHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}

	public int getNameIndex() {
		return e_name_index;
	}
	
	public int getNameLen() {
		return e_name_len;
	}
	
	public int getValueSize() {
		return e_value_size;
	}

	public byte[] getName() {
		return e_name;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
