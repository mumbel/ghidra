package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSXattrHeader implements StructConverter {
	
	public static final String NAME = "f2fs_xattr_header";
	
	private long start_index;
	private long end_index;
	
	private long h_magic;
	private long h_refcount;
	private int[] h_sloadd;
	
	public F2FSXattrHeader() {
	}
	
	public F2FSXattrHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		h_magic = reader.readNextUnsignedInt();
		h_refcount = reader.readNextUnsignedInt();
		h_sloadd = reader.readNextIntArray(4);
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x18;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSXattrHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public long getMagic() {
		return h_magic;
	}
	
	public long getRefcount() {
		return h_refcount;
	}
	
	public int[] getSloadd() {
		return h_sloadd;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
