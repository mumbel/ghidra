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

public class F2FSInodeHeader implements StructConverter {

	public static final String NAME = "f2fs_inode";
	
	private long start_index;
	private long end_index;

	private int i_mode;
	private int i_advise;
	private int i_inline;
	private long i_uid;
	private long i_gid;
	private long i_links;
	private long i_size; //TODO
	private long i_blocks; //TODO
	private long i_atime; //TODO
	private long i_ctime; //TODO
	private long i_mtime; //TODO
	private long i_atime_nsec;
	private long i_ctime_nsec;
	private long i_mtime_nsec;
	private long i_generation;
	private long i_current_depth;
	private long i_xattr_nid;
	private long i_flags;
	private long i_pino;
	private long i_namelen;
	private byte[] i_name; //TODO
	private int i_dir_level;
	private F2FSExtentHeader i_ext;
	
	// TODO union { struct {
	private int i_extra_isize;
	private int i_padding;
	private long i_projid;
	private long i_inode_checksum;
	private long i_crtime; //TODO
	private long i_crtime_nsec;
	private long i_compr_blocks; //TODO
	private int i_compress_algorithm;
	private int i_log_cluster_size;
	private int i_compress_flag;
	private int[] i_extra_end;
	// } struct
	private int[] i_addr; //TODO
	// } union
	
	private int[] i_nid; //TODO

	public F2FSInodeHeader() {
	}

	public F2FSInodeHeader(BinaryReader reader) throws IOException {
		start_index = reader.getPointerIndex();

		i_mode = reader.readNextUnsignedShort();
		i_advise = reader.readNextUnsignedByte();
		i_inline = reader.readNextUnsignedByte();
		i_uid = reader.readNextUnsignedInt();
		i_gid = reader.readNextUnsignedInt();
		i_links = reader.readNextUnsignedInt();
		i_size = reader.readNextLong();
		i_blocks = reader.readNextLong();
		i_atime = reader.readNextLong();
		i_ctime = reader.readNextLong();
		i_mtime = reader.readNextLong();
		i_atime_nsec = reader.readNextUnsignedInt();
		i_ctime_nsec = reader.readNextUnsignedInt();
		i_mtime_nsec = reader.readNextUnsignedInt();
		i_generation = reader.readNextUnsignedInt();
		i_current_depth = reader.readNextUnsignedInt();
		i_xattr_nid = reader.readNextUnsignedInt();
		i_flags = reader.readNextUnsignedInt();
		i_pino = reader.readNextUnsignedInt();
		i_namelen = reader.readNextUnsignedInt();
		assert i_namelen <= F2FSConstants.F2FS_NAME_LEN : "i_namelen: " + i_namelen + "start "+start_index;
		i_name = reader.readNextByteArray(F2FSConstants.F2FS_NAME_LEN);
		i_dir_level = reader.readNextUnsignedByte();
		i_ext = new F2FSExtentHeader(reader);
		
		//TODO  union { struct {
		long tmp_index = reader.getPointerIndex();
		i_extra_isize = reader.readNextUnsignedShort();
		i_padding = reader.readNextUnsignedShort();
		i_projid = reader.readNextUnsignedInt();
		i_inode_checksum = reader.readNextUnsignedInt();
		i_crtime = reader.readNextLong();
		i_crtime_nsec = reader.readNextUnsignedInt();
		i_compr_blocks = reader.readNextLong(); //TODO
		i_compress_algorithm = reader.readNextUnsignedByte();
		i_log_cluster_size = reader.readNextUnsignedByte();
		i_compress_flag = reader.readNextUnsignedShort();
		// rewind... letting i_addr set end of union for size validation
		reader.setPointerIndex(tmp_index);
		i_addr = reader.readNextIntArray(F2FSConstants.DEF_ADDRS_PER_INODE);

		i_nid = reader.readNextIntArray(F2FSConstants.DEF_NIDS_PER_INODE);
		
		end_index = reader.getPointerIndex();
		assert end_index - start_index == 0xfe8 : "end_index " + end_index + ", start_index " + start_index;
		dump();
		
		//TODO
		if ((i_mode & F2FSConstants.S_IFMT) == F2FSConstants.S_IFREG) {
			// regular file
			// file of i_size, with data contained in i_blocks, at i_addr[]
			// what is full filename?
		} else if ((i_mode & F2FSConstants.S_IFMT) == F2FSConstants.S_IFDIR) {
			// directory
		} else if ((i_mode & F2FSConstants.S_IFMT) == F2FSConstants.S_IFLNK) {
			// symbolic link
		} else {
			
		}
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSInodeHeader (s=0x%x, e=0x%x)", start_index, end_index));
		if (i_mode != 0xffff) {
			Msg.debug(this, String.format("\tmode=%o, uid=%d, gid=%d, size=0x%x, blocks=%d, name=%s",
				i_mode, i_uid, i_gid, i_size, i_blocks,
				new String(i_name, StandardCharsets.UTF_8)));
			Msg.debug(this, String.format("gen %x, depth %d, level %d", i_generation, i_current_depth, i_dir_level));
			Msg.debug(this, String.format("i_addrs [%x, %x, %x, %x, %x,...]",
					i_addr[0], i_addr[1], i_addr[2], i_addr[3], i_addr[4]));
			Msg.debug(this, String.format("i_nid [%d, %d, %d, %d, %d]",
					i_nid[0], i_nid[1], i_nid[2], i_nid[3], i_nid[4]));
		}
	}

	public int getMode() {
		return i_mode;
	}

	public int getAdvise() {
		return i_advise;
	}

	public int getInline() {
		return i_inline;
	}

	public long getUid() {
		return i_uid;
	}

	public long getGid() {
		return i_gid;
	}

	public long getLinks() {
		return i_links;
	}

	public long getSize() {
		return i_size;
	}

	public long getBlocks() {
		return i_blocks;
	}

	public long getAtime() {
		return i_atime;
	}

	public long getCtime() {
		return i_ctime;
	}

	public long getMtime() {
		return i_mtime;
	}

	public long getAtimeNsec() {
		return i_atime_nsec;
	}

	public long getCtimeNsec() {
		return i_ctime_nsec;
	}

	public long getMtimeNsec() {
		return i_mtime_nsec;
	}

	public long getGeneration() {
		return i_generation;
	}

	public long getCurrentDepth() {
		return i_current_depth;
	}

	public long getXattrNid() {
		return i_xattr_nid;
	}

	public long getFlags() {
		return i_flags;
	}

	public long getPino() {
		return i_pino;
	}

	public long getNamelen() {
		return i_namelen;
	}

	public byte[] getName() {
		return i_name;
	}

	public int getDirLevel() {
		return i_dir_level;
	}
	
	public F2FSExtentHeader getExt() {
		return i_ext;
	}
	
	public int[] getAddr() {
		//TODO  union { struct {
		return i_addr;
	}
	
	public int[] getNid() {
		return i_nid;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);

		structure.add(DWORD, "i_mode", null);
		structure.add(DWORD, "i_advise", null);
		structure.add(DWORD, "i_inline", null);
		structure.add(DWORD, "i_uid", null);
		structure.add(DWORD, "i_gid", null);
		structure.add(DWORD, "i_links", null);
		structure.add(DWORD, "i_size", null);
		structure.add(DWORD, "i_blocks", null);
		structure.add(DWORD, "i_atime", null);
		structure.add(DWORD, "i_ctime", null);
		structure.add(DWORD, "i_mtime", null);
		structure.add(DWORD, "i_atime_nsec", null);
		structure.add(DWORD, "i_ctime_nsec", null);
		structure.add(DWORD, "i_mtime_nsec", null);
		structure.add(DWORD, "i_generation", null);
		structure.add(DWORD, "i_current_depth", null);
		structure.add(DWORD, "i_xattr_nid", null);
		structure.add(DWORD, "i_flags", null);
		structure.add(DWORD, "i_pino", null);
		structure.add(DWORD, "i_namelen", null);
		structure.add(new ArrayDataType(BYTE, F2FSConstants.F2FS_NAME_LEN, BYTE.getLength()), "i_name", null);
		structure.add(DWORD, "i_dir_level", null);
		structure.add(new F2FSExtentHeader().toDataType(), "i_ext", null);

		/*
		 * union { struct {
		 *  __le16 i_extra_isize;
		 *  __le16 i_padding;
		 *  __le32 i_projid;
		 *  __le32 i_inode_checksum;
		 *  __le32 i_extra_end[0]
		 */
		structure.add(new ArrayDataType(DWORD, F2FSConstants.DEF_ADDRS_PER_INODE, DWORD.getLength()), "i_addr", null);
		structure.add(new ArrayDataType(DWORD, 5, DWORD.getLength()), "i_nid", null);

		return structure;
	}

}
