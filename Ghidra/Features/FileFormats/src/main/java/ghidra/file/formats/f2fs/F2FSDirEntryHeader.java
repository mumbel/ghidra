package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSDirEntryHeader implements StructConverter {
	
	public static final String NAME = "f2fs_dir_entry";
	
	private long start_index;
	private long end_index;

	private long hash_code;
	private long ino;
	private int name_len;
	private int file_type;
	
	public F2FSDirEntryHeader() {
	}
	
	public F2FSDirEntryHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		hash_code = reader.readNextUnsignedInt();
		ino = reader.readNextUnsignedInt();
		name_len = reader.readNextUnsignedShort();
		file_type = reader.readNextUnsignedByte();
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x0;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSDirEntryHeader (s=0x%x, e=0x%x) hash %x ino %d len %d ftype %d",
				start_index, end_index, hash_code, ino, name_len, file_type));
	}
	
	public long getHashCode() {
		return hash_code;
	}
	
	public long getIno() {
		return ino;
	}
	
	public int getNameLen() {
		return name_len;
	}
	
	public int getFileType() {
		return file_type;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "hash_code", null);
		structure.add(DWORD, "ino", null);
		structure.add(WORD, "name_len", null);
		structure.add(BYTE, "file_type", null);


		return structure;
	}

}
