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
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

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
		System.out.print("F2FSFileSystem init, fileSystemName: "+fileSystemName+", provider: "+provider+", reader"+reader);
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
		// TODO Auto-generated method stub
		System.out.println("TODO:  getByteProvider: file: "+file+", monitor: "+monitor);
		return null;
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		System.out.println("DEBUG isValid, monitor: "+monitor);
		long idx = reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET);
		int magic0 = reader.peekNextInt();
		reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE);
		int magic1 = reader.peekNextInt();
		System.out.println("MAGIC: "+magic0+", "+magic1+", "+F2FSConstants.F2FS_SUPER_MAGIC);
		
		reader.setPointerIndex(idx);
		return (magic0 == F2FSConstants.F2FS_SUPER_MAGIC) &&
				(magic1 == F2FSConstants.F2FS_SUPER_MAGIC);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		System.out.println("DEBUG:  open, monitor: "+monitor);
		
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
		System.out.println("DEBUG:  sb0: "+sb0);
		sb0.sanityCheck();
		
		// Superblock (SB)
		// Align to start of duplicate Superblock
		reader.setPointerIndex(F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE);
		sb1 = new F2FSSuperBlockHeader(reader);
		System.out.println("DEBUG:  sb1: "+sb1);
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
		
		System.out.println(String.format("cp11 0x%x, cp12 0x%x, cp21 0x%x, cp22 0x%x",
				cp1.getCheckpointVer(), cp1_2.getCheckpointVer(), cp2.getCheckpointVer(), cp2_2.getCheckpointVer()));
		
		// ehh?
		cur_cp = cp1.getCheckpointVer() > cp2.getCheckpointVer() ? cp1 : cp2;
		
		System.out.println(String.format("s11 0x%x, s12 0x%x, s21 0x%x, s22 0x%x",
				cp1.getCpPackStartSum(), cp1_2.getCpPackStartSum(), cp2.getCpPackStartSum(), cp2_2.getCpPackStartSum()));
		
		System.out.println(String.format("r11 0x%x, r12 0x%x, r21 0x%x, r22 0x%x",
				cp1.getRsvdSegmentCount(), cp1_2.getRsvdSegmentCount(), cp2.getRsvdSegmentCount(), cp2_2.getRsvdSegmentCount()));
	
		sb0.sanityCheckCheckpoint(cur_cp.getRsvdSegmentCount());
		
		F2FSConstants.F2FSCurSegType type = F2FSConstants.F2FSCurSegType.CURSEG_HOT_DATA;
		if ((cur_cp.getCkptFlags() & F2FSConstants.CP_COMPACT_SUM_FLAG) != 0) {
			long start = (sb0.getCpBlkAddr() + cur_cp.getCpPackStartSum()) << F2FSConstants.F2FS_BLKSIZE_BITS;
			// This is the CURSEG_HOT_DATA
			reader.setPointerIndex(start);
			F2FSJournalHeader jnat = new F2FSJournalHeader(reader, F2FSConstants.F2FSJournalType.NAT_JOURNAL);
			for (int nindex = 0; nindex < jnat.getNNats(); nindex++) {
				reader.setPointerIndex(jnat.getNatJ().getEntries()[nindex].getNe().getBlockAddr() << F2FSConstants.F2FS_BLKSIZE_BITS);
				F2FSConstants.F2FSNodeType ntype;//TODO
				ntype = F2FSConstants.F2FSNodeType.TYPE_INODE;
				
				System.out.println(String.format("index 0x%x, %d/%d", reader.getPointerIndex(), nindex, jnat.getNNats()));
				F2FSNodeHeader node_blk = new F2FSNodeHeader(reader, ntype);
			}
			// This is the CURSEG_COLD_DATA
			reader.setPointerIndex(start + F2FSConstants.SUM_JOURNAL_SIZE);
			F2FSJournalHeader jsit = new F2FSJournalHeader(reader, F2FSConstants.F2FSJournalType.SIT_JOURNAL);
			
			for (F2FSConstants.F2FSCurSegType i = F2FSConstants.F2FSCurSegType.CURSEG_HOT_DATA;
					i.ordinal() <= F2FSConstants.F2FSCurSegType.CURSEG_COLD_DATA.ordinal();
					i = F2FSConstants.F2FSCurSegType.values()[i.ordinal() + 1]) {
				System.out.println(String.format("%d SB blocks_per_seg %d, CP cur_data_blkoff[] %d, cur_node_blkoff[] %d",
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
		for (; type.ordinal() <= F2FSConstants.F2FSCurSegType.CURSEG_COLD_NODE.ordinal();
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
					System.out.println(String.format("DATA UMOUNT %x %x %x %x",
							sb0.getCpBlkAddr(),
							cur_cp.getCpPackTotalBlockCount(),
							F2FSConstants.NR_CURSEG_TYPE,
							type.ordinal()));
				} else {
					blk_addr = (sb0.getCpBlkAddr() +
							cur_cp.getCpPackTotalBlockCount() - 
							(F2FSConstants.NR_CURSEG_DATA_TYPE + 1) +
							type.ordinal()) << F2FSConstants.F2FS_BLKSIZE_BITS;
					System.out.println(String.format("DATA no-UMOUNT %x %x %x %x",
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
					System.out.println(String.format("NODE UMOUNT %x %x %x %x",
							sb0.getCpBlkAddr(),
							cur_cp.getCpPackTotalBlockCount(),
							F2FSConstants.NR_CURSEG_NODE_TYPE,
							type.ordinal()));
				} else {
					blk_addr = (sb0.getSsaBlkAddr() + segno) << F2FSConstants.F2FS_BLKSIZE_BITS;
					System.out.println(String.format("NODE no-UMOUNT %x %x", sb0.getSsaBlkAddr(), segno));
				}
			}
			reader.setPointerIndex(blk_addr);
			F2FSSummaryBlockHeader sum_blk = new F2FSSummaryBlockHeader(reader);
			System.out.println(String.format("sum_blk %d, %d, %08x", sum_blk.getJournal().getNSits(), sum_blk.getFooter().getEntryType(),
					sum_blk.getFooter().getCheckSum()));
		}
		
		System.out.println(String.format("segment_count_main %d", sb0.getSegmentCountMain()));
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
		System.out.println(String.format("%0llx", kaddr_crc));
		
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
		
		System.out.println("DEBUG:  WHAT NOW");
		return;
	}

	@Override
	public void close() throws IOException {
		super.close();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		System.out.println("F2FSFileSystem::getListing("+directory+")");
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
