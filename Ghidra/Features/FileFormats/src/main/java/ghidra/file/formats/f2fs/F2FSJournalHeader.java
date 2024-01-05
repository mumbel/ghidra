package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class F2FSJournalHeader implements StructConverter {
	
	public static final String NAME = "f2fs_journal";
	
	private long start_index;
	private long end_index;
	
	private int n_nats;
	private int n_sits;
	private F2FSNatJournalHeader nat_j = null;
	private F2FSSitJournalHeader sit_j = null;
	private F2FSExtraInfoHeader info = null;
	private F2FSConstants.F2FSJournalType jtype;

	public F2FSJournalHeader() {
	}

	public F2FSJournalHeader(BinaryReader reader, F2FSConstants.F2FSJournalType type) throws IOException {
		start_index = reader.getPointerIndex();
		jtype = type;
		if (F2FSConstants.F2FSJournalType.NAT_JOURNAL == jtype) {
			n_nats = reader.readNextUnsignedShort();
			nat_j = new F2FSNatJournalHeader(reader);
		} else if (F2FSConstants.F2FSJournalType.SIT_JOURNAL == jtype) {
			n_sits = reader.readNextUnsignedShort();
			sit_j = new F2FSSitJournalHeader(reader);
		} else {
			reader.readNextUnsignedShort();
			info = new F2FSExtraInfoHeader(reader);
		}
		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.SUM_JOURNAL_SIZE;
		dump();
	}
	
	public void dump() {
		Msg.debug(this, String.format("F2FSJournalHeader %s (s=0x%x, e=0x%x) n_nats=%d,n_sits=%d",
				jtype.name(), start_index, end_index, n_nats, n_sits));
		if (F2FSConstants.F2FSJournalType.NAT_JOURNAL == jtype) {
			for (int i = 0; i < F2FSConstants.NAT_JOURNAL_ENTRIES; i++) {
				Msg.debug(this, String.format("\tnid(%d/%d) = %d, %d, %d, 0x%x",
						i,
						F2FSConstants.NAT_JOURNAL_ENTRIES,
						nat_j.getEntries()[i].getNid(),
						nat_j.getEntries()[i].getNe().getIno(),
						nat_j.getEntries()[i].getNe().getVersion(),
						nat_j.getEntries()[i].getNe().getBlockAddr()));
			}
		} else if (F2FSConstants.F2FSJournalType.SIT_JOURNAL == jtype) {
			for (int i = 0; i < F2FSConstants.SIT_JOURNAL_ENTRIES; i++) {
				Msg.debug(this, String.format("\tsegno(%d/%d) = %d, %d, %d",
						i,
						sit_j.getEntries().length,
						sit_j.getEntries()[i].getSegno(),
						sit_j.getEntries()[i].getSe().getVblocks(),
						sit_j.getEntries()[i].getSe().getMtime()));
			}
		} else {
			Msg.debug(this, String.format("\tf2fs_extra_info.kbytes_written 0x%16x", info.getKbytesWritten()));
		}
	}
	
	public F2FSConstants.F2FSJournalType getType() {
		return jtype;
	}
	
	public int getNNats() {
		assert jtype == F2FSConstants.F2FSJournalType.NAT_JOURNAL;
		return n_nats;
	}
	
	public int getNSits() {
		assert jtype == F2FSConstants.F2FSJournalType.SIT_JOURNAL;
		return n_sits;
	}
	
	public F2FSNatJournalHeader getNatJ() {
		assert jtype == F2FSConstants.F2FSJournalType.NAT_JOURNAL;
		return nat_j;
	}
	
	public F2FSSitJournalHeader getSitJ() {
		assert jtype == F2FSConstants.F2FSJournalType.SIT_JOURNAL;
		return sit_j;
	}
	
	public F2FSExtraInfoHeader getInfo() {
		assert jtype == F2FSConstants.F2FSJournalType.INFO_JOURNAL;
		return info;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		/* union {
		 * __le16 n_nats;
		 * __le16 n_sits;
		 */
		structure.add(WORD, "n", null);
		
		/* union {
		 * struct nat_journal nat_j;
		 * struct sit_journal sit_j;
		 * struct f2fs_extra_info info;
		 */
		structure.add(new F2FSExtraInfoHeader().toDataType(), "info", null);
		
		return structure;
	}

}
