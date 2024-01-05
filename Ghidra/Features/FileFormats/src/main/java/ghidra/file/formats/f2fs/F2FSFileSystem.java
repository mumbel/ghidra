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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.lang.Math;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.GFileSystemBase;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

/*
 * - Blocks
 *     - 4K bytes in size
 * - Segment (segment summary area SSA)
 *     - 512 blocks (2MB)
 *     - segment summary block lists owner of each block
 * - Section
 *     - power of 2 number of segments
 *     - default size 2^^0 (1 segment)
 *     - corresponds to a region
 *     - 6 sections "open" at any time
 *         - data ("hot", "warm", "cold")
 *         - node ("hot", "warm", "cold")
 * - Zone
 *     - collection of sections, default of 1
 *     - makes up the "main"
 *     
 * - inode
 *     - 929 addresses for early blocks
 *     - 923 data block
 *     - 2 direct addresses
 *         - 1018 data
 *     - 2 indirect addresses
 *         - 1018 direct node
 *             - 1018 data
 *     - 1 double-indirect addresses
 *         - 1018 indirect node
 *             - 1018 direct node
 *                 - 1018 data
 *     - 1 extent
 *     - All node blocks mapped by NAT
 *     
 * - NAT (Node Address Table)
 *     - inodes
 *     - indirect indexing blocks
 *     - xattr storage
 *     - address of inode stored in directory is an offset into NAT
 *     - index block stored in inode or another index block is an offset into NAT
 *     
 * - directory
 *     - dentry has attributes for hash, ino, len, type
 *     - dentry consists of 214 slots
 *     - dentry block = bitmap + reserved + dentries[] + filename[]
 *     - series of consecutive hash tables
 *     - first hash table has one bucket, two blocks in size
 *     - second hash table has two buckers, four blocks in size
 *     - ... and so on to 31st table
 *     
 * - superblock
 *     - read only, written at creation in the 2nd block
 * - checkpoint
 *     - writable information that would go into a "superblock"
 *     - two-location, adjacent segments, higher version number is current
 * - segment info table (SIT)
 *     -  74 b/seg
 * 
 */
@FileSystemInfo(type = "f2fs", description = "F2FS", factory = F2FSFileSystem.F2FSFileSystemFactory.class)
public class F2FSFileSystem extends GFileSystemBase {

	private BinaryReader reader;
	private F2FSSuperBlockHeader sb0;
	private F2FSSuperBlockHeader sb1;
	private F2FSCheckpointHeader cp1;
	private F2FSCheckpointHeader cp1_2;
	private F2FSCheckpointHeader cp2;
	private F2FSCheckpointHeader cp2_2;
	private F2FSCheckpointHeader cur_cp;
	
	
	protected F2FSFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
		
		reader = new BinaryReader(provider, true);
		Msg.debug(this, "F2FSFileSystem init, fileSystemName: "+fileSystemName+", provider: "+provider+", reader"+reader);
	}

	public F2FSFileSystem(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) {
		super(targetFSRL.getContainer().getName(), byteProvider);
		reader = new BinaryReader(provider, true);
		this.setFilesystemService(fsService);
		this.setFSRL(targetFSRL);
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
		Msg.debug(this, "TODO:  getByteProvider: file: "+file+", monitor: "+monitor);
		return null;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		Msg.debug(this, "DEBUG isValid, monitor: "+monitor);
		long idx = reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET);
		int magic0 = reader.peekNextInt();
		reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE);
		int magic1 = reader.peekNextInt();
		Msg.debug(this, "MAGIC: "+magic0+", "+magic1+", "+F2FSConstants.F2FS_SUPER_MAGIC);
		
		reader.setPointerIndex(idx);
		return (magic0 == F2FSConstants.F2FS_SUPER_MAGIC) &&
				(magic1 == F2FSConstants.F2FS_SUPER_MAGIC);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		Msg.debug(this, "DEBUG:  open, monitor: "+monitor);
		
		//
		//
		// working through things... this does not do anything yet.
		//
		//
		//
		
		// Superblock (SB)
		// Align to start of Superblock
		reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET);
		sb0 = new F2FSSuperBlockHeader(reader);
		Msg.debug(this, "DEBUG:  sb0: "+sb0);
		sb0.sanityCheck();
		
		// Superblock (SB)
		// Align to start of duplicate Superblock
		reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE);
		sb1 = new F2FSSuperBlockHeader(reader);
		Msg.debug(this, "DEBUG:  sb1: "+sb1);
		sb1.sanityCheck();
		
		// Checkpoint (CP)
		// Align to start of Checkpoint, segment aligned
		long cp_addr_1 = sb0.getCpBlkAddr() << F2FSConstants.F2FS_BLKSIZE_BITS;
		reader.setPointerIndex(cp_addr_1);
		cp1 = new F2FSCheckpointHeader(reader);
		reader.setPointerIndex(cp_addr_1 + ((cp1.getCpPackTotalBlockCount() - 1) << 12));
		cp1_2 = new F2FSCheckpointHeader(reader);
		
		long cp_addr_2 = (sb0.getCpBlkAddr() + (1 << sb0.getLogBlocksPerSeg())) << F2FSConstants.F2FS_BLKSIZE_BITS;
		reader.setPointerIndex(cp_addr_2);
		cp2 = new F2FSCheckpointHeader(reader);
		reader.setPointerIndex(cp_addr_2 + ((cp1.getCpPackTotalBlockCount() - 1) << 12));
		cp2_2 = new F2FSCheckpointHeader(reader);
		
		Msg.debug(this, String.format("cp11 0x%x, cp12 0x%x, cp21 0x%x, cp22 0x%x",
				cp1.getCheckpointVer(), cp1_2.getCheckpointVer(), cp2.getCheckpointVer(), cp2_2.getCheckpointVer()));
		
		// largest version is current
		cur_cp = cp1.getCheckpointVer() > cp2.getCheckpointVer() ? cp1 : cp2;
		
		Msg.debug(this, String.format("s11 0x%x, s12 0x%x, s21 0x%x, s22 0x%x",
				cp1.getCpPackStartSum(), cp1_2.getCpPackStartSum(), cp2.getCpPackStartSum(), cp2_2.getCpPackStartSum()));
		
		Msg.debug(this, String.format("r11 0x%x, r12 0x%x, r21 0x%x, r22 0x%x",
				cp1.getRsvdSegmentCount(), cp1_2.getRsvdSegmentCount(), cp2.getRsvdSegmentCount(), cp2_2.getRsvdSegmentCount()));
	
		sb0.sanityCheckCheckpoint(cur_cp.getRsvdSegmentCount());
		
		Msg.debug(this, String.format("main_blk_addr 0x%x, cp_pack_total_block_count 0x%x, cp_pack_start_sum 0x%x",
				sb0.getMainBlkAddr(),
				cur_cp.getCpPackTotalBlockCount(),
				cur_cp.getCpPackStartSum()));
		int log_type;
		int data_segno, node_segno;
		short data_blkoff, node_blkoff;
		long data_blkaddr, node_blkaddr;
		long tmp_blkaddr = sb0.getMainBlkAddr();// + cur_cp.getCpPackTotalBlockCount();
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_HOT_DATA.ordinal();
		data_segno = cur_cp.getCurDataSegno()[log_type];
		data_blkoff = cur_cp.getCurDataBlkoff()[log_type];
		data_blkaddr = (tmp_blkaddr + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %x, blkoff %x, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type].name(),
				data_segno << F2FSConstants.F2FS_BLKSIZE_BITS,
				data_blkoff << F2FSConstants.F2FS_BLKSIZE_BITS,
				data_blkaddr));
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_WARM_DATA.ordinal();
		data_segno = cur_cp.getCurDataSegno()[log_type];
		data_blkoff = cur_cp.getCurDataBlkoff()[log_type];
		data_blkaddr = (tmp_blkaddr - (F2FSConstants.NR_CURSEG_TYPE + 1) + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %d, blkoff %d, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type].name(),
				data_segno, data_blkoff, data_blkaddr));
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_COLD_DATA.ordinal();
		data_segno = cur_cp.getCurDataSegno()[log_type];
		data_blkoff = cur_cp.getCurDataBlkoff()[log_type];
		data_blkaddr = (tmp_blkaddr - (F2FSConstants.NR_CURSEG_TYPE + 1) + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %d, blkoff %d, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type].name(),
				data_segno, data_blkoff, data_blkaddr));
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_HOT_NODE.ordinal() - F2FSConstants.NR_CURSEG_DATA_TYPE;
		node_segno = cur_cp.getCurNodeSegno()[log_type];
		node_blkoff = cur_cp.getCurNodeBlkoff()[log_type];
		node_blkaddr = (tmp_blkaddr - (F2FSConstants.NR_CURSEG_TYPE + 1) + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %d, blkoff %d, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type + F2FSConstants.NR_CURSEG_DATA_TYPE].name(),
				node_segno, node_blkoff, node_blkaddr));
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_WARM_NODE.ordinal() - F2FSConstants.NR_CURSEG_DATA_TYPE;
		node_segno = cur_cp.getCurNodeSegno()[log_type];
		node_blkoff = cur_cp.getCurNodeBlkoff()[log_type];
		node_blkaddr = (tmp_blkaddr - (F2FSConstants.NR_CURSEG_TYPE + 1) + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %d, blkoff %d, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type + F2FSConstants.NR_CURSEG_DATA_TYPE].name(),
				node_segno, node_blkoff, node_blkaddr));
		
		//
		log_type = F2FSConstants.F2FSCurSegType.CURSEG_COLD_NODE.ordinal() - F2FSConstants.NR_CURSEG_DATA_TYPE;
		node_segno = cur_cp.getCurNodeSegno()[log_type];
		node_blkoff = cur_cp.getCurNodeBlkoff()[log_type];
		node_blkaddr = (tmp_blkaddr - (F2FSConstants.NR_CURSEG_TYPE + 1) + log_type) << F2FSConstants.F2FS_BLKSIZE_BITS;
		Msg.debug(this, String.format("%s, segno %d, blkoff %d, blkaddr 0x%x",
				F2FSConstants.F2FSCurSegType.values()[log_type + F2FSConstants.NR_CURSEG_DATA_TYPE].name(),
				node_segno, node_blkoff, node_blkaddr));

		
		
		F2FSConstants.F2FSCurSegType type = F2FSConstants.F2FSCurSegType.CURSEG_HOT_DATA;
		if ((cur_cp.getCkptFlags() & F2FSConstants.CP_COMPACT_SUM_FLAG) != 0) {
			long start = (sb0.getCpBlkAddr() + cur_cp.getCpPackStartSum()) << F2FSConstants.F2FS_BLKSIZE_BITS;
			// This is the CURSEG_HOT_DATA
			reader.setPointerIndex(start);
			F2FSJournalHeader jnat = new F2FSJournalHeader(reader, F2FSConstants.F2FSJournalType.NAT_JOURNAL);
			for (int nindex = 0; nindex < Math.pow(2, jnat.getNNats()); nindex++) {
				reader.setPointerIndex(jnat.getNatJ().getEntries()[nindex].getNe().getBlockAddr() << F2FSConstants.F2FS_BLKSIZE_BITS);
				F2FSConstants.F2FSNodeType ntype;//TODO
				//ntype = F2FSConstants.F2FSNodeType.TYPE_INODE;
				ntype = F2FSConstants.F2FSNodeType.TYPE_DIRECT_NODE;
				
				Msg.debug(this, String.format("index 0x%x, %d/%d/%d",
						reader.getPointerIndex(),
						nindex,
						jnat.getNNats(),
						jnat.getNatJ().getEntries()));
				F2FSNodeHeader node_blk = new F2FSNodeHeader(reader, ntype);
			}
			// This is the CURSEG_COLD_DATA
			reader.setPointerIndex(start + F2FSConstants.SUM_JOURNAL_SIZE);
			F2FSJournalHeader jsit = new F2FSJournalHeader(reader, F2FSConstants.F2FSJournalType.SIT_JOURNAL);
			
			for (F2FSConstants.F2FSCurSegType i = F2FSConstants.F2FSCurSegType.CURSEG_HOT_DATA;
					i.ordinal() <= F2FSConstants.F2FSCurSegType.CURSEG_COLD_DATA.ordinal();
					i = F2FSConstants.F2FSCurSegType.values()[i.ordinal() + 1]) {
				Msg.debug(this, String.format("%d SB blocks_per_seg %d, CP cur_data_blkoff[] %d, cur_node_blkoff[] %d",
						i.ordinal(),
						1 << sb0.getLogBlocksPerSeg(),
						cur_cp.getCurDataBlkoff()[i.ordinal()],
						cur_cp.getCurNodeBlkoff()[i.ordinal()]));
				
				int blk_off = cur_cp.getAllocType()[i.ordinal()] == F2FSConstants.F2FSSegmentType.SSR.ordinal() ? 
						1 << sb0.getLogBlocksPerSeg() :
							(i.isDataSeg(i.ordinal())) ? cur_cp.getCurDataBlkoff()[i.ordinal()] : 
								cur_cp.getCurNodeBlkoff()[i.ordinal()];
				// lost by here
				assert blk_off < F2FSConstants.ENTRIES_IN_SUM;
				
				for (int j = 0; j < blk_off; j++) {
					
				}
			}
			type = F2FSConstants.F2FSCurSegType.CURSEG_HOT_NODE;
		}
		for (; type.ordinal() < F2FSConstants.F2FSCurSegType.NO_CHECK_TYPE.ordinal();
				type = F2FSConstants.F2FSCurSegType.values()[type.ordinal() + 1]) {
			long blk_addr;
			long segno;
			if (type.isDataSeg(type.ordinal())) {
				segno = cur_cp.getCurDataSegno()[type.ordinal()];
				if ((cur_cp.getCkptFlags() & F2FSConstants.CP_UMOUNT_FLAG) != 0) {
					blk_addr = (sb0.getCpBlkAddr() +
							cur_cp.getCpPackTotalBlockCount() - 
							(F2FSConstants.NR_CURSEG_TYPE + 1) +
							type.ordinal()) << F2FSConstants.F2FS_BLKSIZE_BITS;
					Msg.debug(this, String.format("DATA UMOUNT %x %x %x %x",
							sb0.getCpBlkAddr(),
							cur_cp.getCpPackTotalBlockCount(),
							F2FSConstants.NR_CURSEG_TYPE,
							type.ordinal()));
				} else {
					blk_addr = (sb0.getCpBlkAddr() +
							cur_cp.getCpPackTotalBlockCount() - 
							(F2FSConstants.NR_CURSEG_DATA_TYPE + 1) +
							type.ordinal()) << F2FSConstants.F2FS_BLKSIZE_BITS;
					Msg.debug(this, String.format("DATA no-UMOUNT %x %x %x %x",
							sb0.getCpBlkAddr(),
							cur_cp.getCpPackTotalBlockCount(),
							F2FSConstants.NR_CURSEG_DATA_TYPE,
							type.ordinal()));
				}
			} else {
				segno = cur_cp.getCurDataSegno()[type.ordinal() - F2FSConstants.F2FSCurSegType.CURSEG_HOT_NODE.ordinal()];
				if ((cur_cp.getCkptFlags() & F2FSConstants.CP_UMOUNT_FLAG) != 0) {
					blk_addr = (sb0.getCpBlkAddr() +
							cur_cp.getCpPackTotalBlockCount() - 
							(F2FSConstants.NR_CURSEG_NODE_TYPE + 1) +
							(type.ordinal() - F2FSConstants.F2FSCurSegType.CURSEG_HOT_NODE.ordinal())) << F2FSConstants.F2FS_BLKSIZE_BITS;
					Msg.debug(this, String.format("NODE UMOUNT %x %x %x %x",
							sb0.getCpBlkAddr(),
							cur_cp.getCpPackTotalBlockCount(),
							F2FSConstants.NR_CURSEG_NODE_TYPE,
							type.ordinal()));
				} else {
					blk_addr = (sb0.getSsaBlkAddr() + segno) << F2FSConstants.F2FS_BLKSIZE_BITS;
					Msg.debug(this, String.format("NODE no-UMOUNT %x %x", sb0.getSsaBlkAddr(), segno));
				}
			}
			reader.setPointerIndex(blk_addr);
			F2FSSummaryBlockHeader sum_blk = new F2FSSummaryBlockHeader(reader);
			Msg.debug(this, String.format("sum_blk %d, %d, %08x", sum_blk.getJournal().getNSits(), sum_blk.getFooter().getEntryType(),
					sum_blk.getFooter().getCheckSum()));
		}
		
		Msg.debug(this, String.format("segment_count_main %d", sb0.getSegmentCountMain()));
		for (int i = 0; i < sb0.getSegmentCountMain(); i++) {
			reader.setPointerIndex((i + sb0.getSitBlkAddr()) << F2FSConstants.F2FS_BLKSIZE_BITS);
			F2FSSitBlockHeader sit_blk = new F2FSSitBlockHeader(reader);
		}
		
		// build node manager
		
		// check crc
		long blk = sb0.getCpBlkAddr() + (1 << sb0.getLogBlocksPerSeg());
		long nat_bits_bytes = sb0.getSegmentCountNat() << 5;
		long nat_bits_blocks = ((nat_bits_bytes << 1) + 8 + F2FSConstants.F2FS_BLKSIZE - 1) >> F2FSConstants.F2FS_BLKSIZE_BITS;
		blk -= nat_bits_blocks;
		reader.setPointerIndex(blk);
		long kaddr_crc = reader.readNextLong();
		Msg.debug(this, String.format("%016x", kaddr_crc));
		
		//
		long nr_nat_blks = (sb0.getSegmentCountNat() / 2) << sb0.getLogBlocksPerSeg();
		long nr_nat_entries = nr_nat_blks * F2FSConstants.NAT_ENTRY_PER_BLOCK;
		for (long block_off = 0; block_off < nr_nat_blks; block_off++) {
			long seg_off = block_off >> sb0.getLogBlocksPerSeg();
			long block_addr = sb0.getNatBlkAddr() + (seg_off << sb0.getLogBlocksPerSeg() << 1) +
					(block_off & ((1 << sb0.getLogBlocksPerSeg()) - 1));
			reader.setPointerIndex(block_addr << F2FSConstants.F2FS_BLKSIZE_BITS);
			F2FSNatBlockHeader nat_block = new F2FSNatBlockHeader(reader);
		}
		
		Msg.debug(this, "DEBUG:  WHAT NOW");
		return;
	}

	@Override
	public void close() throws IOException {
		super.close();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		Msg.debug(this, "F2FSFileSystem::getListing("+directory+")");
		List<GFile> fileList = new ArrayList<>();
		
		return fileList;
	}

	public static class F2FSFileSystemFactory
		implements GFileSystemFactoryByteProvider<F2FSFileSystem>,
		GFileSystemProbeByteProvider {

		@Override
		public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {
			return F2FSUtil.isF2FSImage(byteProvider);			
		}

		@Override
		public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {
			F2FSFileSystem fs = new F2FSFileSystem(targetFSRL, byteProvider, fsService, monitor);
			fs.open(monitor);
			return fs;
		}	
	}
}
