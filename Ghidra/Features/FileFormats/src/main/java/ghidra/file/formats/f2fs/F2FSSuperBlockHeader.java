package ghidra.file.formats.f2fs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSSuperBlockHeader implements StructConverter {

	public static final String NAME = "f2fs_super_block";
	
	private long start_index;
	private long end_index;
	
	private long magic;
	private int major_ver;
	private int minor_ver;
	private long log_sectorsize;
	private long log_sectors_per_block;
	private long log_blocksize;
	private long log_blocks_per_seg;
	private long segs_per_sec;
	private long segs_per_zone;
	private long checksum_offset;
	private long block_count; //TODO unsigned
	private long section_count;
	private long segment_count;
	private long segment_count_ckpt;
	private long segment_count_sit;
	private long segment_count_nat;
	private long segment_count_ssa;
	private long segment_count_main;
	private long segment0_blkaddr;
	private long cp_blkaddr;
	private long sit_blkaddr;
	private long nat_blkaddr;
	private long ssa_blkaddr;
	private long main_blkaddr;
	private long root_ino;
	private long node_ino;
	private long meta_ino;
	private byte[] uuid; //TODO unsigned
	private short[] volume_name; //TODO unsigned
	private long extension_count;
	private byte[][] extension_list; //TODO unsigned
	private long cp_payload;
	private byte[] version; //TODO unsigned
	private byte[] init_version; //TODO unsigned
	private long feature;
	private int encryption_level;
	private byte[] encrypt_pw_salt; //TODO unsigned
	private F2FSDeviceHeader[] devs;
	private int qf_ino[]; //TODO unsigned
	private int hot_ext_count;
	private int s_encoding;
	private int s_encoding_flags;
	private byte[] s_stop_reason;
	private byte[] s_errors;
	private byte[] reserved;
	private long crc;
	
	// undefined after devs is 327
	private static final int RESERVED_SIZE = 258;
	
	public F2FSSuperBlockHeader() {
	}
	
	public F2FSSuperBlockHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();
		magic = reader.readNextUnsignedInt();
		major_ver = reader.readNextUnsignedShort();
		minor_ver = reader.readNextUnsignedShort();
		log_sectorsize = reader.readNextUnsignedInt();
		log_sectors_per_block = reader.readNextUnsignedInt();
		log_blocksize = reader.readNextUnsignedInt();
		log_blocks_per_seg = reader.readNextUnsignedInt();
		segs_per_sec = reader.readNextUnsignedInt();
		segs_per_zone = reader.readNextUnsignedInt();
		checksum_offset = reader.readNextUnsignedInt();
		block_count = reader.readNextLong();
		section_count = reader.readNextUnsignedInt();
		segment_count = reader.readNextUnsignedInt();
		segment_count_ckpt = reader.readNextUnsignedInt();
		segment_count_sit = reader.readNextUnsignedInt();
		segment_count_nat = reader.readNextUnsignedInt();
		segment_count_ssa = reader.readNextUnsignedInt();
		segment_count_main = reader.readNextUnsignedInt();
		segment0_blkaddr = reader.readNextUnsignedInt();
		cp_blkaddr = reader.readNextUnsignedInt();
		sit_blkaddr = reader.readNextUnsignedInt();
		nat_blkaddr = reader.readNextUnsignedInt();
		ssa_blkaddr = reader.readNextUnsignedInt();
		main_blkaddr = reader.readNextUnsignedInt();
		root_ino = reader.readNextUnsignedInt();
		node_ino = reader.readNextUnsignedInt();
		meta_ino = reader.readNextUnsignedInt();
		uuid = reader.readNextByteArray(16);
		volume_name = reader.readNextShortArray(F2FSConstants.MAX_VOLUME_NAME);
		extension_count = reader.readNextUnsignedInt();
		extension_list = new byte[F2FSConstants.F2FS_MAX_EXTENSION][];
		for (int i = 0; i < F2FSConstants.F2FS_MAX_EXTENSION; i++) {
			extension_list[i]= reader.readNextByteArray(8);
		}
		cp_payload = reader.readNextUnsignedInt();
		version = reader.readNextByteArray(F2FSConstants.VERSION_LEN);
		init_version = reader.readNextByteArray(F2FSConstants.VERSION_LEN);
		feature = reader.readNextUnsignedInt();
		encryption_level = reader.readNextUnsignedByte();
		encrypt_pw_salt =  reader.readNextByteArray(16);
		devs = new F2FSDeviceHeader[F2FSConstants.MAX_DEVICES];
		for (int i = 0; i < F2FSConstants.MAX_DEVICES; i++) {
			devs[i] = new F2FSDeviceHeader(reader);
		}
		qf_ino = reader.readNextIntArray(F2FSConstants.F2FS_MAX_QUOTAS);
		hot_ext_count = reader.readNextUnsignedByte();
		s_encoding = reader.readNextUnsignedShort();
		s_encoding_flags = reader.readNextUnsignedShort();
		s_stop_reason = reader.readNextByteArray(F2FSConstants.MAX_STOP_REASON);
		reserved = reader.readNextByteArray(RESERVED_SIZE);
		crc = reader.readNextUnsignedInt();

		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xc00;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("Superblock  (start=0x%x, end=0x%x)", start_index, end_index));
		System.out.println(String.format("%d,%d. %08x/%d %08x/%d %08x/%d %08x/%d %08x/%d %08x/%d",
				block_count, segment_count,
				segment0_blkaddr, section_count,
				cp_blkaddr, segment_count_ckpt,
				sit_blkaddr, segment_count_sit,
				nat_blkaddr, segment_count_nat,
				ssa_blkaddr, segment_count_ssa,
				main_blkaddr, segment_count_main));
		System.out.println(String.format("%d %d %d, %d", cp_payload, extension_count, encryption_level, log_blocks_per_seg));
		System.out.println(String.format("version %s", new String(version, StandardCharsets.UTF_8)));
		System.out.println(String.format("version %s", new String(init_version, StandardCharsets.UTF_8)));
		for (int i = 0; i < extension_count; i++) {
			System.out.println(String.format("ext %d:  %s", i, new String(extension_list[i], StandardCharsets.UTF_8)));
		}
	}
	
	public void checkBoundary() throws IOException {
		if (segment0_blkaddr != cp_blkaddr) {
			throw new IOException("Invalid segment0/cp block address");
		}
		if (cp_blkaddr + (segment_count_ckpt << log_blocks_per_seg) != sit_blkaddr) {
			throw new IOException("Invalid cp/sit block address");
		}
		if (sit_blkaddr + (segment_count_sit << log_blocks_per_seg) != nat_blkaddr) {
			throw new IOException("Invalid sit/nat block address");
		}
		if (nat_blkaddr + (segment_count_nat << log_blocks_per_seg) != ssa_blkaddr) {
			throw new IOException("Invalid nat/ssa block address");
		}
		if (ssa_blkaddr + (segment_count_ssa << log_blocks_per_seg) != main_blkaddr) {
			throw new IOException("Invalid ssa/main block address");
		}
		long main_end_blkaddr = main_blkaddr + (segment_count_main << log_blocks_per_seg);
		long seg_end_blkaddr = segment0_blkaddr + (segment_count << log_blocks_per_seg);
		if (main_end_blkaddr > seg_end_blkaddr) {
			throw new IOException("Invalid main/segment0 block address");
		} else if (main_end_blkaddr < seg_end_blkaddr) {
			segment_count = (main_end_blkaddr - segment0_blkaddr) >> log_blocks_per_seg;
		}
	}

	public void sanityCheckCheckpoint(long rsvd_segment_count) throws IOException {
		long total = segment_count_ckpt + segment_count_sit + segment_count_nat + segment_count_nat + segment_count_ssa;
				;
		if (total + rsvd_segment_count >= segment_count) {
			throw new IOException(String.format("Invalid segment count sbi %d + cp %d < total %d",
					total, rsvd_segment_count, segment_count));
		}
	}

	public void sanityCheck() throws IOException {
		if (F2FSConstants.F2FS_SUPER_MAGIC != magic) {
			throw new IOException("Invalid magic "+magic+" does not match expected "+F2FSConstants.F2FS_SUPER_MAGIC);
		}
		if (F2FSConstants.F2FS_BLKSIZE != (1 << log_blocksize)) {
			throw new IOException("Invalid block size");
		}
		if (9 != log_blocks_per_seg) {
			throw new IOException("Invalid blocks per segment");
		}
		if (log_sectorsize > F2FSConstants.F2FS_MAX_LOG_SECTOR_SIZE ||
				log_sectorsize < F2FSConstants.F2FS_MIN_LOG_SECTOR_SIZE) {
			throw new IOException("Invalid sector size");
		}
		if (F2FSConstants.F2FS_MAX_LOG_SECTOR_SIZE != (log_sectors_per_block + log_sectorsize)) {
			throw new IOException("Invalid sector size per block");
		}
		if (node_ino != 1 || meta_ino != 2 || root_ino != 3) {
			throw new IOException("Invalid ino");
		}
		if (segment_count > F2FSConstants.F2FS_MAX_SEGMENT) {
			throw new IOException("Invalid segment count");
		}
		checkBoundary();
	}

	public long getMagic() {
		return magic;
	}

	public int getMajorVer() {
		return major_ver;
	}
	
	public int getMinorVer() {
		return minor_ver;
	}

	public long getLogSectorSize() {
		return log_sectorsize;
	}

	public long getLogSectorsPerBlock() {
		return log_sectors_per_block;
	}

	public long getLogBlockSize() {
		return log_blocksize;
	}

	public long getLogBlocksPerSeg() {
		return log_blocks_per_seg;
	}

	public long getSegsPerSec() {
		return segs_per_sec;
	}

	public long getSegsPerZone() {
		return segs_per_zone;
	}

	public long getChecksumOffset() {
		return checksum_offset;
	}

	public long getBlockCount() {
		return block_count;
	}

	public long getSectionCount() {
		return section_count;
	}

	public long getSegmentCount() {
		return segment_count;
	}

	public long getSegmentCountCkpt() {
		return segment_count_ckpt;
	}

	public long getSegmentCountSit() {
		return segment_count_sit;
	}
	
	public long getSegmentCountNat() {
		return segment_count_nat;
	}
	
	public long getSegmentCountSsa() {
		return segment_count_ssa;
	}
	
	public long getSegmentCountMain() {
		return segment_count_main;
	}
	
	public long getSegment0BlkAddr() {
		return segment0_blkaddr;
	}

	public long getCpBlkAddr() {
		return cp_blkaddr;
	}
	
	public long getSitBlkAddr() {
		return sit_blkaddr;
	}
	
	public long getNatBlkAddr() {
		return nat_blkaddr;
	}
	
	public long getSsaBlkAddr() {
		return ssa_blkaddr;
	}
	
	public long getMainBlkAddr() {
		return main_blkaddr;
	}
	
	public long getRootIno() {
		return root_ino;
	}

	public long getNodeIno() {
		return node_ino;
	}
	
	public long getMetaIno() {
		return meta_ino;
	}
	
	public byte[] getUuid() {
		return uuid;
	}

	public short[] getVolumeName() {
		return volume_name;
	}

	public long getExtensionCount() {
		return extension_count;
	}

	public byte[][] getExtensionList() {
		return extension_list;
	}

	public long getCpPayload() {
		return cp_payload;
	}

	public byte[] getVersion() {
		return version;
	}

	public byte[] getInitVersion() {
		return init_version;
	}

	public long getFeature() {
		return feature;
	}

	public int getEncryptionLevel() {
		return encryption_level;
	}

	public byte[] getEncryptPwSalt() {
		return encrypt_pw_salt;
	}

	public F2FSDeviceHeader[] getDevs() {
		return devs;
	}
	
	public byte[] getReserved() {
		return reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		structure.add(DWORD, "magic", null);
		structure.add(WORD, "major_ver", null);
		structure.add(WORD, "minor_ver", null);
		structure.add(DWORD, "log_sectorsize", null);
		structure.add(DWORD, "log_sectors_per_block", null);
		structure.add(DWORD, "log_blocksize", null);
		structure.add(DWORD, "log_blocks_per_seg", null);
		structure.add(DWORD, "segs_per_sec", null);
		structure.add(DWORD, "segs_per_zone", null);
		structure.add(DWORD, "checksum_offset", null);
		structure.add(QWORD, "block_count", null);
		structure.add(DWORD, "section_count", null);
		structure.add(DWORD, "segment_count", null);
		structure.add(DWORD, "segment_count_ckpt", null);
		structure.add(DWORD, "segment_count_sit", null);
		structure.add(DWORD, "segment_count_nat", null);
		structure.add(DWORD, "segment_count_ssa", null);
		structure.add(DWORD, "segment_count_main", null);
		structure.add(DWORD, "segment0_blkaddr", null);
		structure.add(DWORD, "cp_blkaddr", null);
		structure.add(DWORD, "sit_blkaddr", null);
		structure.add(DWORD, "nat_blkaddr", null);
		structure.add(DWORD, "ssa_blkaddr", null);
		structure.add(DWORD, "main_blkaddr", null);
		structure.add(DWORD, "root_ino", null);
		structure.add(DWORD, "node_ino", null);
		structure.add(DWORD, "meta_ino", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "uuid", null);
		structure.add(new ArrayDataType(WORD, F2FSConstants.MAX_VOLUME_NAME, WORD.getLength()), "volume_name", null);
		structure.add(DWORD, "extension_count", null);
		ArrayDataType ext_item = new ArrayDataType(BYTE, F2FSConstants.F2FS_MAX_EXTENSION, BYTE.getLength());
		structure.add(new ArrayDataType(ext_item, 8, ext_item.getLength()), "extension_list", null);
		structure.add(DWORD, "cp_payload", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.VERSION_LEN, BYTE.getLength()), "version", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.VERSION_LEN, BYTE.getLength()), "init_version", null);
		structure.add(DWORD, "feature", null);
		structure.add(BYTE, "encryption_level", null);
		structure.add(new ArrayDataType(BYTE, 16, BYTE.getLength()), "encrypt_pw_salt", null);
		DataType dev_item = new F2FSDeviceHeader().toDataType();
		structure.add(new ArrayDataType(dev_item, F2FSConstants.MAX_DEVICES, dev_item.getLength()), "devs", null);
		structure.add(new ArrayDataType(BYTE, 327, BYTE.getLength()), "reserved", null);

		return structure;
	}

}














































