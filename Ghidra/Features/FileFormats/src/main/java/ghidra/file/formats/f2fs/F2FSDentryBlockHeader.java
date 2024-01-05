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

public class F2FSDentryBlockHeader implements StructConverter {
	
	public static final String NAME = "f2fs_dentry_block";
	
	private long start_index;
	private long end_index;
	
	private byte[] dentry_bitmap; //TODO
	private byte[] reserved; //TODO
	private F2FSDirEntryHeader[] dentry;
	private byte[][] filename; //TODO
	
	public F2FSDentryBlockHeader() {
	}
	
	public F2FSDentryBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		
		dentry_bitmap = reader.readNextByteArray(F2FSConstants.SIZE_OF_DENTRY_BITMAP);
		reserved = reader.readNextByteArray(F2FSConstants.SIZE_OF_RESERVED);
		dentry = new F2FSDirEntryHeader[F2FSConstants.NR_DENTRY_IN_BLOCK];
		for (int i = 0; i < F2FSConstants.NR_DENTRY_IN_BLOCK; i++) {
			dentry[i] = new F2FSDirEntryHeader(reader);
		}
		filename = new byte[F2FSConstants.NR_DENTRY_IN_BLOCK][];
		for (int i = 0; i < F2FSConstants.NR_DENTRY_IN_BLOCK; i++) {
			filename[i] = reader.readNextByteArray(F2FSConstants.F2FS_SLOT_LEN);
		}
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0x0 : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSDentryBlockHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public byte[] getDentryBitmap() {
		return dentry_bitmap;
	}
	
	public byte[] getReserved() {
		return reserved;
	}
	
	public F2FSDirEntryHeader[] getDentry(){
		return dentry;
	}
	
	public byte[][] getFilename() {
		return filename;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(new ArrayDataType(BYTE, F2FSConstants.SIZE_OF_DENTRY_BITMAP, BYTE.getLength()), "dentry_bitmap", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.SIZE_OF_RESERVED, BYTE.getLength()), "reserved", null);

		DataType entry = new F2FSDirEntryHeader().toDataType();
		structure.add(new ArrayDataType(entry, F2FSConstants.NR_DENTRY_IN_BLOCK, entry.getLength()), "dentry", null);

		DataType fname = new ArrayDataType(BYTE, F2FSConstants.F2FS_SLOT_LEN, BYTE.getLength());
		structure.add(new ArrayDataType(fname, F2FSConstants.NR_DENTRY_IN_BLOCK, fname.getLength()), "filename", null);


		return structure;
	}

}
