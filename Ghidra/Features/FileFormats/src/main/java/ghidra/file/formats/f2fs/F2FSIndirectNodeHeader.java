package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSIndirectNodeHeader implements StructConverter {
	
	public static final String NAME = "indirect_node";
	
	private long start_index;
	private long end_index;
	
	private int[] nid; //TODO
	
	public F2FSIndirectNodeHeader(){
	}
	
	public F2FSIndirectNodeHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		nid = reader.readNextIntArray(F2FSConstants.NIDS_PER_BLOCK);
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.NIDS_PER_BLOCK * 4 : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSIndirectNodeHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public int[] getNid() {
		return nid;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
