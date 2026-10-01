package com.trilead.ssh2.channel;

import com.trilead.ssh2.packets.PacketChannelOpenConfirmation;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.transport.ITransportConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

/**
 * The receive window a session channel offers the server, and the buffers behind it, follow the size given to
 * {@link ChannelManager#openSessionChannel(int)}.
 */
@ExtendWith(MockitoExtension.class)
public class ChannelWindowTest {
	private static final int REMOTE_ID = 7;

	@Mock
	private ITransportConnection transport;

	private ChannelManager channelManager;

	@BeforeEach
	public void setUp() {
		channelManager = new ChannelManager(transport);
	}

	/** Confirms every SSH_MSG_CHANNEL_OPEN right away, as a server would. */
	private void confirmChannelOpens() throws IOException {
		doAnswer(invocation -> {
			byte[] msg = invocation.getArgument(0);
			if (msg[0] == Packets.SSH_MSG_CHANNEL_OPEN) {
				byte[] confirmation = new PacketChannelOpenConfirmation(openedLocalId(msg), REMOTE_ID, 1 << 20, 32768)
						.getPayload();
				channelManager.msgChannelOpenConfirmation(confirmation, confirmation.length);
			}
			return null;
		}).when(transport).sendMessage(any(byte[].class));
	}

	@Test
	public void sessionChannelOffersItsWindowAndTakesThatMuchData() throws IOException {
		confirmChannelOpens();
		Channel channel = channelManager.openSessionChannel(100_000);

		assertEquals(100_000, offeredWindow(sentMessages().get(0)));

		// Three times the default window, before the client reads anything.
		for (int i = 0; i < 3; i++)
			deliver(channel, 30_000);
		assertEquals(90_000, readAll(channel, 90_000));

		// Reading frees the whole buffer, so the window goes back up to its full size.
		byte[] adjust = lastSentMessage();
		assertEquals(Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST, adjust[0]);
		assertEquals(90_000, uint32(adjust, 5));
	}

	@Test
	public void defaultSessionChannelKeepsTheDefaultWindow() throws IOException {
		confirmChannelOpens();
		Channel channel = channelManager.openSessionChannel();

		assertEquals(Channel.CHANNEL_BUFFER_SIZE, offeredWindow(sentMessages().get(0)));
		IOException e = assertThrows(IOException.class, () -> deliver(channel, Channel.CHANNEL_BUFFER_SIZE + 1));
		assertTrue(e.getMessage().contains("does not fit into window"), e.getMessage());
	}

	@Test
	public void nonPositiveWindowIsRejected() {
		assertThrows(IllegalArgumentException.class, () -> new Channel(channelManager, 0));
	}

	private void deliver(Channel channel, int length) throws IOException {
		byte[] msg = new byte[9 + length];
		msg[0] = Packets.SSH_MSG_CHANNEL_DATA;
		putUint32(msg, 1, channel.localID);
		putUint32(msg, 5, length);
		channelManager.msgChannelData(msg, msg.length);
	}

	private int readAll(Channel channel, int length) throws IOException {
		byte[] target = new byte[length];
		int read = 0;
		while (read < length) {
			int n = channelManager.getChannelData(channel, false, target, read, length - read);
			if (n <= 0)
				break;
			read += n;
		}
		return read;
	}

	private List<byte[]> sentMessages() throws IOException {
		ArgumentCaptor<byte[]> captor = ArgumentCaptor.forClass(byte[].class);
		verify(transport, atLeastOnce()).sendMessage(captor.capture());
		return captor.getAllValues();
	}

	private byte[] lastSentMessage() throws IOException {
		List<byte[]> messages = sentMessages();
		return messages.get(messages.size() - 1);
	}

	/** SSH_MSG_CHANNEL_OPEN: byte type, string channel type, uint32 sender channel, uint32 window, uint32 max packet. */
	private static int offeredWindow(byte[] channelOpen) throws IOException {
		TypesReader tr = new TypesReader(channelOpen);
		tr.readByte();
		tr.readString();
		tr.readUINT32();
		return tr.readUINT32();
	}

	private static int openedLocalId(byte[] channelOpen) throws IOException {
		TypesReader tr = new TypesReader(channelOpen);
		tr.readByte();
		tr.readString();
		return tr.readUINT32();
	}

	private static int uint32(byte[] b, int off) {
		return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
	}

	private static void putUint32(byte[] b, int off, int value) {
		b[off] = (byte) (value >> 24);
		b[off + 1] = (byte) (value >> 16);
		b[off + 2] = (byte) (value >> 8);
		b[off + 3] = (byte) value;
	}
}
