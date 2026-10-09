/*
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * a.) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * b.) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * c.) Neither the name of Trilead nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.trilead.ssh2.compression;

import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * @author Kenny Root
 *
 */
public class Zlib implements ICompressor {
	static private final int DEFAULT_BUF_SIZE = 4096;
	static private final int LEVEL = 5;

	private Deflater deflate;
	private byte[] deflate_tmpbuf;

	private Inflater inflate;
	private byte[] inflate_tmpbuf;
	private byte[] inflated_buf;

	public Zlib() {
		deflate = new Deflater(LEVEL);
		inflate = new Inflater();

		deflate_tmpbuf = new byte[DEFAULT_BUF_SIZE];
		inflate_tmpbuf = new byte[DEFAULT_BUF_SIZE];
		inflated_buf = new byte[DEFAULT_BUF_SIZE];
	}

	public boolean canCompressPreauth() {
		return true;
	}

	public int getBufferSize() {
		return DEFAULT_BUF_SIZE;
	}

	public int compress(byte[] buf, int start, int len, byte[] output) {
		deflate.setInput(buf, start, len - start);

		if ((buf.length + 1024) > deflate_tmpbuf.length) {
			deflate_tmpbuf = new byte[buf.length + 1024];
		}

		int outputlen = deflate.deflate(deflate_tmpbuf, 0, output.length, Deflater.SYNC_FLUSH);

		if (deflate.getAdler() == 0) {
			System.err.println("compress: compression failure");
		}

		if (!deflate.finished() && deflate.getTotalIn() < len - start) {
			System.err.println("compress: deflated data too large");
		}

		System.arraycopy(deflate_tmpbuf, 0, output, 0, outputlen);

		return outputlen;
	}

	public byte[] uncompress(byte[] buffer, int start, int[] length) {
		int inflated_end = 0;

		inflate.setInput(buffer, start, length[0]);

		// Inflate until the Inflater has nothing left to give. needsInput() alone is not enough: when an inflate()
		// call fills the whole output buffer, the Inflater may have consumed all of the input while still holding
		// inflated bytes, which would otherwise come out at the start of the next packet.
		while (true) {
			try {
				int decompressed = inflate.inflate(inflate_tmpbuf, 0, DEFAULT_BUF_SIZE);

				if (decompressed > 0) {
					if (inflated_buf.length < inflated_end + decompressed) {
						byte[] foo = new byte[Math.max(inflated_end + decompressed, inflated_buf.length * 2)];
						System.arraycopy(inflated_buf, 0, foo, 0, inflated_end);
						inflated_buf = foo;
					}
					System.arraycopy(inflate_tmpbuf, 0, inflated_buf, inflated_end, decompressed);
					inflated_end += decompressed;
				} else if (inflate.needsInput() || inflate.finished() || inflate.needsDictionary()) {
					break;
				}
			} catch (java.util.zip.DataFormatException e) {
				System.err.println("uncompress: inflate error: " + e.getMessage());
				return null;
			}
		}

		if (inflated_end > buffer.length - start) {
			byte[] foo = new byte[inflated_end + start];
			System.arraycopy(buffer, 0, foo, 0, start);
			System.arraycopy(inflated_buf, 0, foo, start, inflated_end);
			buffer = foo;
		} else {
			System.arraycopy(inflated_buf, 0, buffer, start, inflated_end);
		}
		length[0] = inflated_end;
		return buffer;
	}
}
