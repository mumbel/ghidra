package ghidra.file.formats.f2fs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSDeviceHeader implements StructConverter {

	public static final String NAME = "f2fs_device";
	
	private long start_index;
	private long end_index;
	
	private byte[] path;
	private long total_segments;
	
	public F2FSDeviceHeader() {		
	}

	public F2FSDeviceHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		path = reader.readNextByteArray(F2FSConstants.MAX_PATH_LEN);
		total_segments = reader.readNextUnsignedInt();
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x44;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("total_segments %d, path=%s", total_segments, new String(path, StandardCharsets.UTF_8)));
	}
	
	public byte[] getPath() {
		return path;
	}
	
	public long getTotalSegments() {
		return total_segments;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(new ArrayDataType(BYTE, F2FSConstants.MAX_PATH_LEN, BYTE.getLength()), "path", null);
		structure.add(DWORD, "total_segments", null);

		return structure;
	}

}
