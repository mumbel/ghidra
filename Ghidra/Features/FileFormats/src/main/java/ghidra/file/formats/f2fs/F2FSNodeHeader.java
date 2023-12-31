package ghidra.file.formats.f2fs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class F2FSNodeHeader implements StructConverter {

	public static final String NAME = "f2fs_node";
	
	private long start_index;
	private long end_index;
	F2FSConstants.F2FSNodeType ntype;
	
	private F2FSInodeHeader i;
	private F2FSDirectNodeHeader dn;
	private F2FSIndirectNodeHeader in;
	private F2FSNodeFooterHeader footer;
	
	public F2FSNodeHeader() {
	}
	
	public F2FSNodeHeader(BinaryReader reader, F2FSConstants.F2FSNodeType type) throws IOException {
		ntype = type;
		start_index = reader.getPointerIndex();
		
		// going to read footer first and come back to start
		reader.setPointerIndex(start_index + 0xfe8);
		footer = new F2FSNodeFooterHeader(reader);
		reader.setPointerIndex(start_index);
		
		if (footer.getFlag() == 9 || footer.getFlag() == 0xffffffff || footer.getFlag() == -1 || footer.getNid() == 4294967295L || footer.getNid() == -1) {
			//TODO  this gets garbage... is it a direct or indirect?
			//TODO  this should maybe determine type
			long value = footer.getFlag() >> F2FSConstants.F2FSBitShift.OFFSET_BIT_SHIFT.ordinal();
			System.out.println("TODO: ....... flag "+footer.getFlag()+", ofs "+value);
			reader.setPointerIndex(start_index + F2FSConstants.F2FS_BLKSIZE);
			end_index = reader.getPointerIndex();
			dump();
			return;
		}
		
		if (F2FSConstants.F2FSNodeType.TYPE_DIRECT_NODE == ntype) {
			dn = new F2FSDirectNodeHeader(reader);
		} else if (F2FSConstants.F2FSNodeType.TYPE_INDIRECT_NODE == ntype) {
			in = new F2FSIndirectNodeHeader(reader);
		} else if (F2FSConstants.F2FSNodeType.TYPE_DOUBLE_INDIRECT_NODE == ntype) {
			throw new IOException("TODO  double indirect node");
		} else if (F2FSConstants.F2FSNodeType.TYPE_INODE == ntype) {
			i = new F2FSInodeHeader(reader);
		} else if (F2FSConstants.F2FSNodeType.TYPE_XATTR == ntype) {
			throw new IOException("TODO  xattr");
		} else {
			throw new IOException("TODO  unknown type");
		}
		
		// skip past previously read footer
		reader.setPointerIndex(reader.getPointerIndex() + 0x18);

		end_index = reader.getPointerIndex();
		assert end_index - start_index == F2FSConstants.F2FS_BLKSIZE : "end_index " + end_index + ", start_index " + start_index;
		dump();
	}
	
	public void dump() {
		System.out.println(String.format("F2FSNodeHeader (s=0x%x, e=0x%x)", start_index, end_index));
	}
	
	public F2FSDirectNodeHeader getDn() {
		assert F2FSConstants.F2FSNodeType.TYPE_DIRECT_NODE == ntype;
		return dn;
	}
	
	public F2FSIndirectNodeHeader getIn() {
		assert F2FSConstants.F2FSNodeType.TYPE_INDIRECT_NODE == ntype;
		return in;
	}
	
	public F2FSInodeHeader getI() {
		assert F2FSConstants.F2FSNodeType.TYPE_INODE == ntype;
		return i;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(NAME, 0);
		
		/* TODO   union {
		 * TODO   direct_node dn
		 * TODO   indirect_node in;
		 */
		structure.add(new F2FSInodeHeader().toDataType(), "i", null);
		structure.add(new F2FSNodeFooterHeader().toDataType(), "footer", null);
		
		return structure;
	}

}
