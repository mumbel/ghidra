/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.file.formats.f2fs;

public class F2FSConstants {
	
	// Super Block Magic Number, int 32 little endian (f2f52010 1020f5f2)
	public static final long F2FS_SUPER_MAGIC = 0xf2f52010L;
	public static final int F2FS_SUPER_MAGIC_SIZE = 4;
	public static final int F2FS_SUPER_OFFSET = 1024;
	
	//
	public static final int MAX_VOLUME_NAME = 512;
	
	//
	public static final int F2FS_MAX_EXTENSION = 64;
	public static final int F2FS_EXTENSION_LEN = 8;

	//
	public static final int VERSION_LEN = 256;
	
	//
	public static final int MAX_PATH_LEN = 64;
	
	//
	public static final int F2FS_NAME_LEN = 255;

	//
	public static final int MAX_DEVICES = 8;
	
	
	public static final int MAX_ACTIVE_LOGS	= 16;
	public static final int MAX_ACTIVE_NODE_LOGS = 8;
	public static final int MAX_ACTIVE_DATA_LOGS = 8;
	
	
	public static final int F2FS_FEATURE_ENCRYPT		= 0x0001;
	public static final int F2FS_FEATURE_BLKZONED		= 0x0002;
	public static final int F2FS_FEATURE_ATOMIC_WRITE	= 0x0004;
	public static final int F2FS_FEATURE_EXTRA_ATTR		= 0x0008;
	public static final int F2FS_FEATURE_PRJQUOTA		= 0x0010;
	public static final int F2FS_FEATURE_INODE_CHKSUM	= 0x0020;
	
	
	// checkpoint
	public static final int CP_RESIZEFS_FLAG         = 0x00004000;
	public static final int CP_DISABLED_QUICK_FLAG   = 0x00002000;
	public static final int CP_DISABLED_FLAG         = 0x00001000;
	public static final int CP_QUOTA_NEED_FSCK_FLAG  = 0x00000800;
	public static final int CP_LARGE_NAT_BITMAP_FLAG = 0x00000400;
	public static final int CP_NOCRC_RECOVERY_FLAG   = 0x00000200;
	public static final int CP_TRIMMED_FLAG		 	 = 0x00000100;
	public static final int CP_NAT_BITS_FLAG	 	 = 0x00000080;
	public static final int CP_CRC_RECOVERY_FLAG	 = 0x00000040;
	public static final int CP_FASTBOOT_FLAG		 = 0x00000020;
	public static final int CP_FSCK_FLAG			 = 0x00000010;
	public static final int CP_ERROR_FLAG			 = 0x00000008;
	public static final int CP_COMPACT_SUM_FLAG		 = 0x00000004;
	public static final int CP_ORPHAN_PRESENT_FLAG	 = 0x00000002;
	public static final int CP_UMOUNT_FLAG			 = 0x00000001;

	public static final int F2FS_CP_PACKS = 2;
    
	//
	public static final int F2FS_ORPHANS_PER_BLOCK = 1020;

	//
	public static final int DEF_ADDRS_PER_INODE = 923;
	public static final int DEF_NIDS_PER_INODE = 5;

	//
	public static final int F2FS_INLINE_XATTR       = 0x01;    /* file inline xattr flag */
	public static final int F2FS_INLINE_DATA        = 0x02;    /* file inline data flag */
	public static final int F2FS_INLINE_DENTRY      = 0x04;    /* file inline dentry flag */
	public static final int F2FS_DATA_EXIST         = 0x08;    /* file inline data exist flag */
	public static final int F2FS_INLINE_DOTS        = 0x10;    /* file having implicit dot dentries */
	public static final int F2FS_EXTRA_ATTR         = 0x20;    /* file having extra attribute */
	public static final int F2FS_PIN_FILE           = 0x40;    /* file should not be gced */
	public static final int F2FS_COMPRESS_RELEASED  = 0x80;    /* file released compressed blocks */
    
	//
	public static final int SIT_VBLOCK_MAP_SIZE = 64;

	//
	public static final int F2FS_BLKSIZE = 4096;
	public static final int PAGE_CACHE_SIZE = F2FS_BLKSIZE;
	public static final int F2FS_BLKSIZE_BITS = 12;
	
	//
	public static final int ENTRIES_IN_SUM = 512;
	
	//
	public static final int SUM_FOOTER_SIZE = 5;
	
	//
	public static final int SUMMARY_SIZE = 7;
	
	//
	public static final int SUM_ENTRIES_SIZE = (SUMMARY_SIZE * ENTRIES_IN_SUM);
	
	//
	public static final int SUM_JOURNAL_SIZE = (F2FS_BLKSIZE - SUM_FOOTER_SIZE - SUM_ENTRIES_SIZE);

	public static final int EXTRA_INFO_RESERVED = SUM_JOURNAL_SIZE - 2 - 8;

	//
	public static final int NR_DENTRY_IN_BLOCK = 214;
	public static final int BITS_PER_BYTE = 8;
	public static final int SIZE_OF_DENTRY_BITMAP = ((NR_DENTRY_IN_BLOCK + BITS_PER_BYTE - 1) / BITS_PER_BYTE);
	public static final int F2FS_SLOT_LEN = 8;
	public static final int SIZE_OF_DIR_ENTRY = 11;
	public static final int SIZE_OF_RESERVED = (4096 - ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP));
	
	//
	public static final long F2FS_MAX_LOG_SECTOR_SIZE = 12;
	public static final long F2FS_MIN_LOG_SECTOR_SIZE = 9;
	public static final long F2FS_MAX_SEGMENT = ((16 * 1024 * 1024) / 2);
	public static final long F2FS_SEGMENT_SIZE = (2 * 1024 * 1024);
	
	// 
	public static final int NAT_ENTRY_PER_BLOCK = PAGE_CACHE_SIZE / (1+4+4);
	public static final int SIT_ENTRY_PER_BLOCK = PAGE_CACHE_SIZE / (2+SIT_VBLOCK_MAP_SIZE+8);
	
	//
	public static final int NAT_JOURNAL_ENTRIES = (SUM_JOURNAL_SIZE - 2) / (4 + 1 + 4 + 4);
	public static final int NAT_JOURNAL_RESERVED = (SUM_JOURNAL_SIZE - 2) % (4 + 1 + 4 + 4);
	public static final int SIT_JOURNAL_ENTRIES = (SUM_JOURNAL_SIZE - 2) / (4 + 2 + 64 + 8);
	public static final int SIT_JOURNAL_RESERVED = (SUM_JOURNAL_SIZE - 2) % (4 + 2 + 64 + 8);
	
	//TODO ghidra type enum?
	public enum F2FSJournalType {
		NAT_JOURNAL, // = 0
		SIT_JOURNAL,
		INFO_JOURNAL; // not sure what this should be
	}
	
	// 6 total logs, 3 for data/node
	public static final int NR_CURSEG_DATA_TYPE = 3;                                                                 
	public static final int NR_CURSEG_NODE_TYPE = 3;                                                                
	public static final int NR_CURSEG_TYPE = NR_CURSEG_DATA_TYPE + NR_CURSEG_NODE_TYPE;
	
	public static final int ADDRS_PER_BLOCK = 1018; 
	public static final int NIDS_PER_BLOCK = 1018;
	
	//TODO ghidra type enum?
	public enum F2FSCurSegType {
		CURSEG_HOT_DATA,   // contains dentry blocks
		CURSEG_WARM_DATA,  // contains data blocks except hot and cold data blocks 
		CURSEG_COLD_DATA,  // contains multimedia data or migrated data blocks
		CURSEG_HOT_NODE,   // contains direct node blocks of directories
		CURSEG_WARM_NODE,  // contains direct node blocks except hot node blocks
		CURSEG_COLD_NODE,  // contains indirect node blocks
		NO_CHECK_TYPE;
		
		public boolean isDataSeg(int i) {
			return  i == CURSEG_HOT_DATA.ordinal() || i == CURSEG_WARM_DATA.ordinal() || i == CURSEG_COLD_DATA.ordinal();
		}
		public boolean isNodeSeg(int i) {
			return  i == CURSEG_HOT_NODE.ordinal() || i == CURSEG_WARM_NODE.ordinal() || i == CURSEG_COLD_NODE.ordinal();
		}
	}
	
	public enum F2FSSegmentType {
		LFS,
		SSR
	}
	
	public enum F2FSNodeType {
		TYPE_INODE(37),
		TYPE_DIRECT_NODE(43),
		TYPE_INDIRECT_NODE(53),
		TYPE_DOUBLE_INDIRECT_NODE(67),
		TYPE_XATTR(77);
		
		private final int value;

		private F2FSNodeType(int val) {
			value = val;
		}
		public int getValue() {
			return value;
		}
	}
	
	public enum F2FSBitShift {
		COLD_BIT_SHIFT,
		FSYNC_BIT_SHIFT,
		DENT_BIT_SHIFT,
		OFFSET_BIT_SHIFT,
	}
	
	//TODO  are these really not anywhere common?
	public static final int S_IFMT     = 0170000; //   bit mask for the file type bit field

	public static final int S_IFSOCK   = 0140000; //   socket
	public static final int S_IFLNK    = 0120000; //   symbolic link
	public static final int S_IFREG    = 0100000; //   regular file
	public static final int S_IFBLK    = 0060000; //   block device
	public static final int S_IFDIR    = 0040000; //   directory
	public static final int S_IFCHR    = 0020000; //   character device
	public static final int S_IFIFO    = 0010000; //   FIFO

	public static final int S_ISUID    = 04000; //   set-user-ID bit (see execve(2))
	public static final int S_ISGID    = 02000; //   set-group-ID bit (see below)
	public static final int S_ISVTX    = 01000; //   sticky bit (see below)

	public static final int S_IRWXU    = 00700; //   owner has read, write, and execute permission
	public static final int S_IRUSR    = 00400; //   owner has read permission
	public static final int S_IWUSR    = 00200; //   owner has write permission
	public static final int S_IXUSR    = 00100; //   owner has execute permission

	public static final int S_IRWXG    = 00070; //   group has read, write, and execute permission
	public static final int S_IRGRP    = 00040; //   group has read permission
	public static final int S_IWGRP    = 00020; //   group has write permission
	public static final int S_IXGRP    = 00010; //   group has execute permission

	public static final int S_IRWXO    = 00007; //   others (not in group) have read,  write,  and execute permission
    public static final int S_IROTH    = 00004; //   others have read permission
    public static final int S_IWOTH    = 00002; //   others have write permission
    public static final int S_IXOTH    = 00001; //  others have execute permission
    
    
	public static final int F2FS_MAX_QUOTAS = 3;
	public static final int MAX_STOP_REASON = 32;
	public static final int MAX_F2FS_ERRORS = 16;
	
	
	public enum F2FSFileType {
		F2FS_FT_UNKNOWN,                                                                             
        F2FS_FT_REG_FILE,                                                                            
        F2FS_FT_DIR,                                                                                 
        F2FS_FT_CHRDEV,                                                                              
        F2FS_FT_BLKDEV,                                                                              
        F2FS_FT_FIFO,                                                                                
        F2FS_FT_SOCK,                                                                                
        F2FS_FT_SYMLINK,                                                                             
        F2FS_FT_MAX,                                                                                                                                                         
        F2FS_FT_ORPHAN,                                                                              
        F2FS_FT_XATTR,  
	}
}
