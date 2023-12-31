package ghidra.file.formats.f2fs;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.io.IOException;

public class F2FSUtil {

	private static final long CRCPOLY_LE = 0xedb88320;

	private long calcCrc32(long crc, byte[] buf, int len) {
		int index = 0;
		while (len-- > 0) {
			crc = (crc & 0xffffffff) ^ (buf[index] & 0xffffffff);
			for (int i = 0; i < 8; i++) {
				long tmp = (crc & 1) == 0 ? 0 : CRCPOLY_LE;
				crc = ((crc >> 1) & 0xffffffff) ^ (tmp & 0xffffffff);
			}
		}
		return crc;
	}
	public boolean crcValid(BinaryReader reader, long crc, long start, long end) throws IOException {
		return crc == calcCrc32((long)F2FSConstants.F2FS_SUPER_MAGIC,
				reader.readByteArray(start, (int)(end - start)),
				(int)(end - start));
	}
	public final static boolean isF2FSImage(byte[] bytes) {
		if (bytes.length < F2FSConstants.F2FS_SUPER_OFFSET +
				F2FSConstants.F2FS_BLKSIZE + F2FSConstants.F2FS_BLKSIZE) {
			return false;
		}
		return ((byte)0xf2 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + 3] &&
				(byte)0xf5 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + 2] &&
				(byte)0x20 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + 1] &&
				(byte)0x10 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + 0] &&
				(byte)0xf2 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE + 3] &&
				(byte)0xf5 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE + 2] &&
				(byte)0x20 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE + 1] &&
				(byte)0x10 == bytes[F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE + 0]);
	}	
	public final static boolean isF2FSImage(ByteProvider provider) {
		try{
			byte[] bytes = provider.readBytes(0, F2FSConstants.F2FS_SUPER_OFFSET +
					F2FSConstants.F2FS_BLKSIZE + F2FSConstants.F2FS_BLKSIZE);
			return isF2FSImage(bytes);
		} catch (Exception e) {
		}
		return false;
	}
	public final static boolean isF2FSImage(Program program) {
		byte[] bytes0 = new byte[F2FSConstants.F2FS_SUPER_MAGIC_SIZE];
		byte[] bytes1 = new byte[F2FSConstants.F2FS_SUPER_MAGIC_SIZE];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address.add(F2FSConstants.F2FS_SUPER_OFFSET), bytes0);
			program.getMemory().getBytes(address.add(F2FSConstants.F2FS_SUPER_OFFSET + F2FSConstants.F2FS_BLKSIZE), bytes0);
		} catch (Exception e) {
			return false;
		}
		return ((byte)0xf2 == bytes0[3] &&
				(byte)0xf5 == bytes0[2] &&
				(byte)0x20 == bytes0[1] &&
				(byte)0x10 == bytes0[0] &&
				(byte)0xf2 == bytes1[3] &&
				(byte)0xf5 == bytes1[2] &&
				(byte)0x20 == bytes1[1] &&
				(byte)0x10 == bytes1[0]);
	}
}
