package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSExtentHeader implements StructConverter {
	
	public static final String NAME = "f2fs_extent";
	
	private long start_index;
	private long end_index;

	private long fofs;
	private long blk_addr;
	private long len;
	
	public F2FSExtentHeader() {
	}
	
	public F2FSExtentHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();

		fofs = reader.readNextUnsignedInt();
		blk_addr = reader.readNextUnsignedInt();
		len = reader.readNextUnsignedInt();
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x0c : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSExtentHeader (s=0x%x, e=0x%x) fofs %x, blk_addr %x, len %d",
				start_index, end_index, fofs, blk_addr, len));		
	}

	public long getFofs() {
		return fofs;
	}
	
	public long getBlkAddr() {
		return blk_addr;
	}
	
	public long getLen() {
		return len;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "fofs", null);
		structure.add(DWORD, "blk_addr", null);
		structure.add(DWORD, "len", null);
		
		return structure;
	}

}
