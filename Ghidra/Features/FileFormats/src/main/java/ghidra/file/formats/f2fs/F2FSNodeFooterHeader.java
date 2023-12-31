package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNodeFooterHeader implements StructConverter {

	public static final String NAME = "node_footer";
	
	private long start_index;
	private long end_index;
	
	private long nid;
	private long ino;
	private long flag;
	private long cp_ver; //TODO
	private long next_blkaddr;
	
	public F2FSNodeFooterHeader() {		
	}
	
	public F2FSNodeFooterHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		nid = reader.readNextUnsignedInt();
		ino = reader.readNextUnsignedInt();
		flag = reader.readNextUnsignedInt();
		cp_ver = reader.readNextLong();
		next_blkaddr = reader.readNextUnsignedInt();
	
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x18 : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}

	public void dump() {
		System.out.println(String.format("F2FSNodeFooterHeader (s=0x%x, e=0x%x) nid %d, ino %d, flag 0x%x, cp_ver 0x%x, next_blkaddr 0x%x",
				start_index, end_index, nid, ino, flag, cp_ver, next_blkaddr));
	}

	public long getNid() {
		return nid;
	}
	
	public long getIno() {
		return ino;
	}
	
	public long getFlag() {
		return flag;
	}
	
	public long getCpVer() {
		return cp_ver;
	}
	
	public long getNextBlkaddr() {
		return next_blkaddr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "nid", null);
		structure.add(DWORD, "ino", null);
		structure.add(DWORD, "flag", null);
		structure.add(QWORD, "cp_ver", null);
		structure.add(DWORD, "next_blkaddr", null);
		
		return structure;
	}

}
