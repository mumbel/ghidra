package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSCheckpointHeader implements StructConverter {

	public static final String NAME = "f2fs_checkpoint";
	
	private long start_index;
	private long end_index;
	
	private long checkpoint_ver; //TODO
	private long user_block_count; //TODO
	private long valid_block_count; //TODO
	private long rsvd_segment_count;
	private long overprov_segment_count;
	private long free_segment_count;
	private int[] cur_node_segno; //TODO
	private short[] cur_node_blkoff; //TODO
	private int[] cur_data_segno; //TODO
	private short[] cur_data_blkoff; //TODO
	private long ckpt_flags;
	private long cp_pack_total_block_count;
	private long cp_pack_start_sum;
	private long valid_node_count;
	private long valid_inode_count;
	private long next_free_nid;
	private long sit_ver_bitmap_bytesize;
	private long nat_ver_bitmap_bytesize;
	private long checksum_offset;
	private long elapsed_time; //TODO
	private byte[] alloc_type; //TODO
	private byte[] sit_nat_version_bitmap; //TODO

	public F2FSCheckpointHeader() {
	}
	
	public F2FSCheckpointHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		checkpoint_ver = reader.readNextLong();
		user_block_count = reader.readNextLong();
		valid_block_count = reader.readNextLong();
		rsvd_segment_count = reader.readNextUnsignedInt();
		overprov_segment_count = reader.readNextUnsignedInt();
		free_segment_count = reader.readNextUnsignedInt();
		assert reader.getPointerIndex() - start_index == 0x24;
		cur_node_segno = reader.readNextIntArray(F2FSConstants.MAX_ACTIVE_NODE_LOGS);
		cur_node_blkoff = reader.readNextShortArray(F2FSConstants.MAX_ACTIVE_NODE_LOGS);
		assert reader.getPointerIndex() - start_index == 0x54;
		cur_data_segno = reader.readNextIntArray(F2FSConstants.MAX_ACTIVE_DATA_LOGS);
		cur_data_blkoff = reader.readNextShortArray(F2FSConstants.MAX_ACTIVE_DATA_LOGS);
		assert reader.getPointerIndex() - start_index == 0x84;
		ckpt_flags = reader.readNextUnsignedInt();
		cp_pack_total_block_count = reader.readNextUnsignedInt();
		cp_pack_start_sum = reader.readNextUnsignedInt();
		valid_node_count = reader.readNextUnsignedInt();
		valid_inode_count = reader.readNextUnsignedInt();
		next_free_nid = reader.readNextUnsignedInt();
		sit_ver_bitmap_bytesize = reader.readNextUnsignedInt();
		nat_ver_bitmap_bytesize = reader.readNextUnsignedInt();
		checksum_offset = reader.readNextUnsignedInt();
		assert reader.getPointerIndex() - start_index == 0xa8;
		elapsed_time = reader.readNextLong();
		assert reader.getPointerIndex() - start_index == 0xb0;
		alloc_type = reader.readNextByteArray(F2FSConstants.MAX_ACTIVE_LOGS);
		assert reader.getPointerIndex() - start_index == 0xc0;
		sit_nat_version_bitmap = reader.readNextByteArray(1);
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xc1;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("Checkpoint (start=0x%x, end=0x%x)", start_index, end_index));
		System.out.println(String.format("CP version: %08x, pack total %d", checkpoint_ver, cp_pack_total_block_count));
		System.out.println("\tuser count: "+user_block_count+", valid count: "+valid_block_count+
				", rsvd: "+rsvd_segment_count+", over: "+overprov_segment_count+", free: "+free_segment_count);
		System.out.println(String.format("\t%x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x",
				cur_node_segno[0], cur_node_blkoff[0],
				cur_node_segno[1], cur_node_blkoff[1],
				cur_node_segno[2], cur_node_blkoff[2],
				cur_node_segno[3], cur_node_blkoff[3],
				cur_node_segno[4], cur_node_blkoff[4],
				cur_node_segno[5], cur_node_blkoff[5],
				cur_node_segno[6], cur_node_blkoff[6],
				cur_node_segno[7], cur_node_blkoff[7]));
		System.out.println(String.format("\t%x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x, %x/%x",
				cur_data_segno[0], cur_data_blkoff[0],
				cur_data_segno[1], cur_data_blkoff[1],
				cur_data_segno[2], cur_data_blkoff[2],
				cur_data_segno[3], cur_data_blkoff[3],
				cur_data_segno[4], cur_data_blkoff[4],
				cur_data_segno[5], cur_data_blkoff[5],
				cur_data_segno[6], cur_data_blkoff[6],
				cur_data_segno[7], cur_data_blkoff[7]));
		System.out.println("ckpt_flags: "+ckpt_flags);
		System.out.println("checksum offset: "+checksum_offset);
		System.out.println("elapsed_time: "+elapsed_time);
	}
	
	public boolean validateCheckpoint() {
		return true;
	}
	
	public long getCheckpointVer() {
		return checkpoint_ver;
	}
	
	public long getUserBlockCount() {
		return user_block_count;
	}
	
	public long getValidBlockCount() {
		return valid_block_count;
	}
	
	public long getRsvdSegmentCount() {
		return rsvd_segment_count;
	}
	
	public long getOverprovSegmentCount() {
		return overprov_segment_count;
	}
	
	public long getFreeSegmentCount() {
		return free_segment_count;
	}
	
	public int[] getCurNodeSegno() {
		return cur_node_segno;
	}
	
	public short[] getCurNodeBlkoff() {
		return cur_node_blkoff;
	}

	public int[] getCurDataSegno() {
		return cur_data_segno;
	}
	
	public short[] getCurDataBlkoff() {
		return cur_data_blkoff;
	}
	
	public long getCkptFlags() {
		return ckpt_flags;
	}
	
	public long getCpPackTotalBlockCount() {
		return cp_pack_total_block_count;
	}
	
	public long getCpPackStartSum() {
		return cp_pack_start_sum;
	}
	
	public long getValidNodeCount() {
		return valid_node_count;
	}
	
	public long getValidInodeCount() {
		return valid_inode_count;
	}
	
	public long getNextFreeNid() {
		return next_free_nid;
	}
	
	public long getSitVerBitmapBytesize() {
		return sit_ver_bitmap_bytesize;
	}
	
	public long getNatVerBitmapBytesize() {
		return nat_ver_bitmap_bytesize;
	}
	
	public long getChecksumOffset() {
		return checksum_offset;
	}
	
	public long getElapsedTime() {
		return elapsed_time;
	}
	
	public byte[] getAllocType() {
		return alloc_type;
	}
	
	public byte[] getSitNatVersionBitmap() {
		return sit_nat_version_bitmap;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(QWORD, "checkpoint_ver", null);
		structure.add(QWORD, "user_block_count", null);
		structure.add(QWORD, "valid_block_count", null);
		structure.add(DWORD, "rsvd_segment_count", null);
		structure.add(DWORD, "overprov_segment_count", null);
		structure.add(DWORD, "free_segment_count", null);
		structure.add(new ArrayDataType(DWORD, F2FSConstants.MAX_ACTIVE_NODE_LOGS, DWORD.getLength()), "cur_node_segno", null);
		structure.add(new ArrayDataType(WORD, F2FSConstants.MAX_ACTIVE_NODE_LOGS, WORD.getLength()), "cur_node_blkoff", null);
		structure.add(new ArrayDataType(DWORD, F2FSConstants.MAX_ACTIVE_DATA_LOGS, DWORD.getLength()), "cur_data_segno", null);
		structure.add(new ArrayDataType(WORD, F2FSConstants.MAX_ACTIVE_DATA_LOGS, WORD.getLength()), "cur_data_blkoff", null);
		structure.add(DWORD, "ckpt_flags", null);
		structure.add(DWORD, "cp_pack_total_block_count", null);
		structure.add(DWORD, "cp_pack_start_sum", null);
		structure.add(DWORD, "valid_node_count", null);
		structure.add(DWORD, "valid_inode_count", null);
		structure.add(DWORD, "next_free_nid", null);
		structure.add(DWORD, "sit_ver_bitmap_bytesize", null);
		structure.add(DWORD, "nat_ver_bitmap_bytesize", null);
		structure.add(DWORD, "checksum_offset", null);
		structure.add(QWORD, "elapsed_time", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.MAX_ACTIVE_LOGS, BYTE.getLength()), "alloc_type", null);
		structure.add(new ArrayDataType(BYTE, 1, BYTE.getLength()), "sit_nat_version_bitmap", null);		

		return structure;
	}

}
