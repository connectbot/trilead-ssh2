package com.trilead.ssh2.compression;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class ZlibTest {
	/**
	 * Two packets of one compression stream as an OpenSSH server sends them: zlib level 6, one Z_PARTIAL_FLUSH per
	 * packet (Java's Deflater cannot produce that flush, so the bytes come from Python's zlib:
	 * {@code compressobj(6)}, then {@code compress(payload) + flush(Z_PARTIAL_FLUSH)} for each payload).
	 *
	 * The first payload is 4104 bytes, all but the first one 'a'. Inflating it into the 4096-byte buffer fills the
	 * buffer while the Inflater has already consumed all 24 input bytes and still holds the last 8 inflated
	 * bytes: those must end this packet, not start the next one.
	 */
	private static final byte[] PACKET_1 = bytes(0x78, 0x9c, 0xec, 0xc1, 0x01, 0x09, 0x00, 0x00, 0x00, 0x02, 0xa0,
			0xa7, 0x41, 0xff, 0x4f, 0x34, 0x24, 0x35, 0x05, 0x00, 0x00, 0x00, 0x5e, 0x4c);
	private static final byte[] PACKET_2 = bytes(0x00, 0xc5, 0xe5, 0xa5, 0x56, 0x94, 0x28, 0x14, 0x24, 0x26, 0x67,
			0xa7, 0x96, 0x00, 0x04);

	@Test
	public void bytesLeftInTheInflaterWhenItsBufferFillsStayInTheirPacket() {
		byte[] payload1 = new byte[4104];
		Arrays.fill(payload1, (byte) 'a');
		payload1[0] = '^';
		byte[] payload2 = "^next packet".getBytes(StandardCharsets.US_ASCII);

		Zlib zlib = new Zlib();

		assertArrayEquals(payload1, uncompress(zlib, PACKET_1));
		assertArrayEquals(payload2, uncompress(zlib, PACKET_2));
	}

	/** Uncompresses one packet the way TransportConnection does: the payload after a 5-byte packet header. */
	private static byte[] uncompress(Zlib zlib, byte[] packet) {
		int start = 5;
		byte[] buffer = new byte[start + packet.length];
		System.arraycopy(packet, 0, buffer, start, packet.length);
		int[] length = { packet.length };

		byte[] result = zlib.uncompress(buffer, start, length);

		assertNotNull(result, "inflate error");
		return Arrays.copyOfRange(result, start, start + length[0]);
	}

	private static byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++)
			result[i] = (byte) values[i];
		return result;
	}
}
