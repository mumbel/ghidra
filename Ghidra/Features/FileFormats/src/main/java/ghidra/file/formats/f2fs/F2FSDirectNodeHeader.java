package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSDirectNodeHeader implements StructConverter {
	
	public static final String NAME = "direct_node";
	
	private long start_index;
	private long end_index;
	
	private int[] addr; //TODO
	
	public F2FSDirectNodeHeader(){
	}
	
	public F2FSDirectNodeHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		addr = reader.readNextIntArray(F2FSConstants.ADDRS_PER_BLOCK);

		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.ADDRS_PER_BLOCK * 4 : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSDirectNodeHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}

	public int[] getAddr() {
		return addr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
