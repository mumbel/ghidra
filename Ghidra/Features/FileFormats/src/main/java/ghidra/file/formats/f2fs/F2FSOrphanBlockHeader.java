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

public class F2FSOrphanBlockHeader implements StructConverter {
	
	public static final String NAME = "f2fs_orphan_block";
	
	private long start_index;
	private long end_index;
	
	private int[] ino;
	private long reserved;
	private int blk_addr;
	private int blk_count;
	private long entry_count;
	private long check_sum;
	
	public F2FSOrphanBlockHeader(){
	}

	public F2FSOrphanBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		ino = reader.readNextIntArray(F2FSConstants.F2FS_ORPHANS_PER_BLOCK);
		reserved = reader.readNextUnsignedInt();
		blk_addr = reader.readNextUnsignedShort();
		blk_count = reader.readNextUnsignedShort();
		entry_count = reader.readNextUnsignedInt();
		check_sum = reader.readNextUnsignedInt();
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x4a;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSOrphanBlockHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public int[] getIno() {
		return ino;
	}
	
	public long getReserved() {
		return reserved;
	}
	
	public int getBlkAddr() {
		return blk_addr;
	}
	
	public int getBlkCount() {
		return blk_count;
	}
	
	public long getEntryCount() {
		return entry_count;
	}
	
	public long getCheckSum() {
		return check_sum;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(new ArrayDataType(DWORD, F2FSConstants.F2FS_ORPHANS_PER_BLOCK, DWORD.getLength()), "ino", null);
		structure.add(DWORD, "reserved", null);
		structure.add(WORD, "blk_addr", null);
		structure.add(WORD, "blk_count", null);
		structure.add(DWORD, "entry_count", null);
		structure.add(DWORD, "check_sum", null);
		
		return structure;
	}

}
