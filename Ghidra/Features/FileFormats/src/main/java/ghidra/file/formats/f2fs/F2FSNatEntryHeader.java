package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNatEntryHeader implements StructConverter {

	public static final String NAME = "f2fs_nat_entry";
	
	private long start_index;
	private long end_index;
	
	private int version;
	private long ino;
	private long block_addr;
	
	public F2FSNatEntryHeader() {
	}
	
	public F2FSNatEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		version = reader.readNextUnsignedByte();
		ino = reader.readNextUnsignedInt();
		block_addr = reader.readNextUnsignedInt();
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x9;
		dump();
	}
	
	public void dump() {
		if (version == 0 && ino == 0 && block_addr == 0)
			return;
		Msg.debug(this, String.format("F2FSNatEntryHeader (s=0x%x, e=0x%x), ver %d, ino %d, addr 0x%x", start_index, end_index, version, ino, block_addr));
	}
	
	public int getVersion() {
		return version;
	}
	
	public long getIno() {
		return ino;
	}
	
	public long getBlockAddr() {
		return block_addr;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(BYTE, "version", null);
		structure.add(DWORD, "ino", null);
		structure.add(DWORD, "block_Addr", null);
		
		return structure;
	}

}
