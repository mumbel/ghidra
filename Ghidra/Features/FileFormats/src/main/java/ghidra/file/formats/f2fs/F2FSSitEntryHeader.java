package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSitEntryHeader implements StructConverter {

	public static final String NAME = "f2fs_sit_entry";
	
	private long start_index;
	private long end_index;
	
	private int vblocks;
	private byte[] valid_map; //TODO
	private long mtime; //TODO
	
	public F2FSSitEntryHeader() {
	}
	
	public F2FSSitEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		vblocks = reader.readNextUnsignedShort();
		valid_map = reader.readNextByteArray(F2FSConstants.SIT_VBLOCK_MAP_SIZE);
		mtime = reader.readNextLong();		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x4a;
		dump();
	}
	
	public void dump() {
		if (vblocks == 0xffff || mtime == -1)
			return;
		if (vblocks == 0 && mtime == 0)
			return;
		System.out.println(String.format("F2FSSitEntryHeader (s=0x%x, e=0x%x) vblocks %d, mtime %d", start_index, end_index, vblocks, mtime));
	}
	
	public int getVblocks() {
		return vblocks;
	}
	
	public byte[] getValidMap() {
		return valid_map;
	}
	
	public long getMtime() {
		return mtime;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(WORD, "vblocks", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.SIT_VBLOCK_MAP_SIZE, BYTE.getLength()), "valid_map", null);
		structure.add(QWORD, "mtime", null);
		
		return structure;
	}

}
