
package com.trilead.ssh2.channel;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.trilead.ssh2.AuthAgentCallback;
import com.trilead.ssh2.ChannelCondition;
import com.trilead.ssh2.ConnectionInfo;
import com.trilead.ssh2.ExtendedServerHostKeyVerifier;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.PacketChannelAuthAgentReq;
import com.trilead.ssh2.packets.PacketChannelOpenConfirmation;
import com.trilead.ssh2.packets.PacketChannelOpenFailure;
import com.trilead.ssh2.packets.PacketChannelTrileadPing;
import com.trilead.ssh2.packets.PacketGlobalCancelForwardRequest;
import com.trilead.ssh2.packets.PacketGlobalForwardRequest;
import com.trilead.ssh2.packets.PacketGlobalHostkeys;
import com.trilead.ssh2.packets.PacketGlobalHostkeysProve;
import com.trilead.ssh2.packets.PacketGlobalTrileadPing;
import com.trilead.ssh2.packets.PacketOpenDirectTCPIPChannel;
import com.trilead.ssh2.packets.PacketOpenSessionChannel;
import com.trilead.ssh2.packets.PacketSessionExecCommand;
import com.trilead.ssh2.packets.PacketSessionPtyRequest;
import com.trilead.ssh2.packets.PacketSessionPtyResize;
import com.trilead.ssh2.packets.PacketSessionStartShell;
import com.trilead.ssh2.packets.PacketSessionSubsystemRequest;
import com.trilead.ssh2.packets.PacketSessionX11Request;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.RSASHA256Verify;
import com.trilead.ssh2.signature.RSASHA512Verify;
import com.trilead.ssh2.signature.SSHSignature;
import com.trilead.ssh2.transport.ITransportConnection;
import com.trilead.ssh2.transport.MessageHandler;

/**
 * ChannelManager coordinates all SSH channels over a single transport connection.
 * <p>
 * This class is the core of the SSH channel layer, managing:
 * <ul>
 * <li>Channel lifecycle (open, close, EOF)</li>
 * <li>Data transmission and flow control</li>
 * <li>Channel requests (PTY, X11, exec, shell, subsystem)</li>
 * <li>Global requests (port forwarding, ping)</li>
 * <li>SSH message routing to appropriate channel handlers</li>
 * </ul>
 * <p>
 * Architecture: ChannelManager implements {@link MessageHandler} to receive
 * SSH packets in the range 80-100 (channel-related messages) from the
 * {@link com.trilead.ssh2.transport.TransportManager}. It maintains a registry
 * of active channels and routes messages to the appropriate channel instance.
 * <p>
 * The manager handles both synchronous operations (like opening a session channel)
 * and asynchronous message processing (incoming data, window adjustments, channel close).
 * <p>
 * Thread safety: All channel operations are synchronized on the channels list or
 * individual channel objects to ensure proper concurrency control.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: ChannelManager.java,v 1.2 2008/03/03 07:01:36 cplattne Exp $
 * @see Channel
 * @see MessageHandler
 * @see com.trilead.ssh2.transport.ITransportConnection
 */
public class ChannelManager implements MessageHandler
{
	private static final Logger log = Logger.getLogger(ChannelManager.class);

	private static final int MAX_ADVERTISED_HOSTKEYS = 20;
	private static final int MAX_KEYS_TO_PROVE = 10;

	private final HashMap<String, X11ServerData> x11_magic_cookies = new HashMap<>();

	private final ITransportConnection tm;

	private final List<Channel> channels = new ArrayList<>();
	private int nextLocalChannel = 100;
	private boolean shutdown = false;
	private int globalSuccessCounter = 0;
	private int globalFailedCounter = 0;

	private volatile HostkeysProveRequest pendingHostkeysProve = null;
	private final Object hostkeysProveLock = new Object();

	private static class HostkeysProveRequest
	{
		final List<byte[]> requestedKeys;
		final String requestName;
		final String hostname;
		final int port;
		List<byte[]> responseSignatures;
		boolean succeeded;
		boolean completed;

		HostkeysProveRequest(List<byte[]> keys, String reqName, String host, int p)
		{
			this.requestedKeys = keys;
			this.requestName = reqName;
			this.hostname = host;
			this.port = p;
			this.succeeded = false;
			this.completed = false;
		}
	}

	private final HashMap<Integer, RemoteForwardingData> remoteForwardings = new HashMap<>();

	private AuthAgentCallback authAgent;

	private final List<IChannelWorkerThread> listenerThreads = new ArrayList<>();

	private boolean listenerThreadsAllowed = true;

	public ChannelManager(ITransportConnection tm)
	{
		this.tm = tm;
		tm.registerMessageHandler(this, 80, 100);
	}

	private Channel getChannel(int id)
	{
		synchronized (channels)
		{
			for (Channel c : channels)
			{
				if (c.localID == id)
					return c;
			}
		}
		return null;
	}

	private void removeChannel(int id)
	{
		synchronized (channels)
		{
			for (int i = 0; i < channels.size(); i++)
			{
				Channel c = channels.get(i);
				if (c.localID == id)
				{
					channels.remove(i);
					break;
				}
			}
		}
	}

	private int addChannel(Channel c)
	{
		synchronized (channels)
		{
			channels.add(c);
			return nextLocalChannel++;
		}
	}

	private void waitUntilChannelOpen(Channel c) throws IOException
	{
		synchronized (c)
		{
			while (c.state == Channel.STATE_OPENING)
			{
				try
				{
					c.wait();
				}
				catch (InterruptedException ignore)
				{
				}
			}

			if (c.state != Channel.STATE_OPEN)
			{
				removeChannel(c.localID);

				String detail = c.getReasonClosed();

				if (detail == null)
					detail = "state: " + c.state;

				throw new IOException("Could not open channel (" + detail + ")");
			}
		}
	}

	private boolean waitForGlobalRequestResult() throws IOException
	{
		synchronized (channels)
		{
			while ((globalSuccessCounter == 0) && (globalFailedCounter == 0))
			{
				if (shutdown)
				{
					throw new IOException("The connection is being shutdown");
				}

				try
				{
					channels.wait();
				}
				catch (InterruptedException ignore)
				{
				}
			}

			if ((globalFailedCounter == 0) && (globalSuccessCounter == 1))
				return true;

			if ((globalFailedCounter == 1) && (globalSuccessCounter == 0))
				return false;

			throw new IOException("Illegal state. The server sent " + globalSuccessCounter
					+ " SSH_MSG_REQUEST_SUCCESS and " + globalFailedCounter + " SSH_MSG_REQUEST_FAILURE messages.");
		}
	}

	private boolean waitForChannelRequestResult(Channel c) throws IOException
	{
		synchronized (c)
		{
			while ((c.successCounter == 0) && (c.failedCounter == 0))
			{
				if (c.state != Channel.STATE_OPEN)
				{
					String detail = c.getReasonClosed();

					if (detail == null)
						detail = "state: " + c.state;

					throw new IOException("This SSH2 channel is not open (" + detail + ")");
				}

				try
				{
					c.wait();
				}
				catch (InterruptedException ignore)
				{
				}
			}

			if ((c.failedCounter == 0) && (c.successCounter == 1))
				return true;

			if ((c.failedCounter == 1) && (c.successCounter == 0))
				return false;

			throw new IOException("Illegal state. The server sent " + c.successCounter
					+ " SSH_MSG_CHANNEL_SUCCESS and " + c.failedCounter + " SSH_MSG_CHANNEL_FAILURE messages.");
		}
	}

	public void registerX11Cookie(String hexFakeCookie, X11ServerData data)
	{
		synchronized (x11_magic_cookies)
		{
			x11_magic_cookies.put(hexFakeCookie, data);
		}
	}

	public void unRegisterX11Cookie(String hexFakeCookie, boolean killChannels)
	{
		if (hexFakeCookie == null)
			throw new IllegalStateException("hexFakeCookie may not be null");

		synchronized (x11_magic_cookies)
		{
			x11_magic_cookies.remove(hexFakeCookie);
		}

		if (!killChannels)
			return;

		if (log.isEnabled())
			log.log(50, "Closing all X11 channels for the given fake cookie");

		List<Channel> channel_copy;

		synchronized (channels)
		{
			channel_copy = new ArrayList<>(channels);
		}

		for (int i = 0; i < channel_copy.size(); i++)
		{
			Channel c = channel_copy.get(i);

			synchronized (c)
			{
				if (!hexFakeCookie.equals(c.hexX11FakeCookie))
					continue;
			}

			try
			{
				closeChannel(c, "Closing X11 channel since the corresponding session is closing", true);
			}
			catch (IOException e)
			{
			}
		}
	}

	public X11ServerData checkX11Cookie(String hexFakeCookie)
	{
		synchronized (x11_magic_cookies)
		{
			if (hexFakeCookie != null)
				return x11_magic_cookies.get(hexFakeCookie);
		}
		return null;
	}

	public void closeAllChannels()
	{
		if (log.isEnabled())
			log.log(50, "Closing all channels");

		List<Channel> channel_copy;

		synchronized (channels)
		{
			channel_copy = new ArrayList<>(channels);
		}

		for (int i = 0; i < channel_copy.size(); i++)
		{
			Channel c = channel_copy.get(i);
			try
			{
				closeChannel(c, "Closing all channels", true);
			}
			catch (IOException e)
			{
			}
		}
	}

	public void closeChannel(Channel c, String reason, boolean force) throws IOException
	{
		byte msg[] = new byte[5];

		synchronized (c)
		{
			if (force)
			{
				c.state = Channel.STATE_CLOSED;
				c.EOF = true;
			}

			c.setReasonClosed(reason);

			msg[0] = Packets.SSH_MSG_CHANNEL_CLOSE;
			msg[1] = (byte) (c.remoteID >> 24);
			msg[2] = (byte) (c.remoteID >> 16);
			msg[3] = (byte) (c.remoteID >> 8);
			msg[4] = (byte) (c.remoteID);

			c.notifyAll();
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				return;
			tm.sendMessage(msg);
			c.closeMessageSent = true;
		}

		if (log.isEnabled())
			log.log(50, "Sent SSH_MSG_CHANNEL_CLOSE (channel " + c.localID + ")");
	}

	public void sendEOF(Channel c) throws IOException
	{
		byte[] msg = new byte[5];

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				return;

			msg[0] = Packets.SSH_MSG_CHANNEL_EOF;
			msg[1] = (byte) (c.remoteID >> 24);
			msg[2] = (byte) (c.remoteID >> 16);
			msg[3] = (byte) (c.remoteID >> 8);
			msg[4] = (byte) (c.remoteID);
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				return;
			tm.sendMessage(msg);
		}

		if (log.isEnabled())
			log.log(50, "Sent EOF (Channel " + c.localID + "/" + c.remoteID + ")");
	}

	public void sendOpenConfirmation(Channel c) throws IOException
	{
		PacketChannelOpenConfirmation pcoc = null;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPENING)
				return;

			c.state = Channel.STATE_OPEN;

			pcoc = new PacketChannelOpenConfirmation(c.remoteID, c.localID, c.localWindow, c.localMaxPacketSize);
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				return;
			tm.sendMessage(pcoc.getPayload());
		}
	}

	public void sendData(Channel c, byte[] buffer, int pos, int len) throws IOException
	{
		while (len > 0)
		{
			int thislen = 0;
			byte[] msg;

			synchronized (c)
			{
				while (true)
				{
					if (c.state == Channel.STATE_CLOSED)
						throw new IOException("SSH channel is closed. (" + c.getReasonClosed() + ")");

					if (c.state != Channel.STATE_OPEN)
						throw new IOException("SSH channel in strange state. (" + c.state + ")");

					if (c.remoteWindow != 0)
						break;

					try
					{
						c.wait();
					}
					catch (InterruptedException ignore)
					{
					}
				}

				/* len > 0, no sign extension can happen when comparing */

				thislen = (c.remoteWindow >= len) ? len : (int) c.remoteWindow;

				int estimatedMaxDataLen = c.remoteMaxPacketSize - (tm.getPacketOverheadEstimate() + 9);

				/* The worst case scenario =) a true bottleneck */

				if (estimatedMaxDataLen <= 0)
				{
					estimatedMaxDataLen = 1;
				}

				if (thislen > estimatedMaxDataLen)
					thislen = estimatedMaxDataLen;

				c.remoteWindow -= thislen;

				msg = new byte[1 + 8 + thislen];

				msg[0] = Packets.SSH_MSG_CHANNEL_DATA;
				msg[1] = (byte) (c.remoteID >> 24);
				msg[2] = (byte) (c.remoteID >> 16);
				msg[3] = (byte) (c.remoteID >> 8);
				msg[4] = (byte) (c.remoteID);
				msg[5] = (byte) (thislen >> 24);
				msg[6] = (byte) (thislen >> 16);
				msg[7] = (byte) (thislen >> 8);
				msg[8] = (byte) (thislen);

				System.arraycopy(buffer, pos, msg, 9, thislen);
			}

			synchronized (c.channelSendLock)
			{
				if (c.closeMessageSent)
					throw new IOException("SSH channel is closed. (" + c.getReasonClosed() + ")");

				tm.sendMessage(msg);
			}

			pos += thislen;
			len -= thislen;
		}
	}

	public int requestGlobalForward(String bindAddress, int bindPort, String targetAddress, int targetPort)
			throws IOException
	{
		RemoteForwardingData rfd = new RemoteForwardingData();

		rfd.bindAddress = bindAddress;
		rfd.bindPort = bindPort;
		rfd.targetAddress = targetAddress;
		rfd.targetPort = targetPort;

		synchronized (remoteForwardings)
		{
			if (remoteForwardings.get(bindPort) != null)
			{
				throw new IOException("There is already a forwarding for remote port " + bindPort);
			}

			remoteForwardings.put(bindPort, rfd);
		}

		synchronized (channels)
		{
			globalSuccessCounter = globalFailedCounter = 0;
		}

		PacketGlobalForwardRequest pgf = new PacketGlobalForwardRequest(true, bindAddress, bindPort);
		tm.sendMessage(pgf.getPayload());

		if (log.isEnabled())
			log.log(50, "Requesting a remote forwarding ('" + bindAddress + "', " + bindPort + ")");

		try
		{
			if (!waitForGlobalRequestResult())
				throw new IOException("The server denied the request (did you enable port forwarding?)");
		}
		catch (IOException e)
		{
			synchronized (remoteForwardings)
			{
				remoteForwardings.remove(rfd.bindPort);
			}
			throw e;
		}

		return bindPort;
	}

	public void requestCancelGlobalForward(int bindPort) throws IOException
	{
		RemoteForwardingData rfd = null;

		synchronized (remoteForwardings)
		{
			rfd = remoteForwardings.get(bindPort);

			if (rfd == null)
				throw new IOException("Sorry, there is no known remote forwarding for remote port " + bindPort);
		}

		synchronized (channels)
		{
			globalSuccessCounter = globalFailedCounter = 0;
		}

		PacketGlobalCancelForwardRequest pgcf = new PacketGlobalCancelForwardRequest(true, rfd.bindAddress,
				rfd.bindPort);
		tm.sendMessage(pgcf.getPayload());

		if (log.isEnabled())
			log.log(50, "Requesting cancelation of remote forward ('" + rfd.bindAddress + "', " + rfd.bindPort + ")");

		try
		{
			if (!waitForGlobalRequestResult())
				throw new IOException("The server denied the request.");
		}
		finally
		{
			synchronized (remoteForwardings)
			{
				/* Only now we are sure that no more forwarded connections will arrive */
				remoteForwardings.remove(rfd.bindPort);
			}
		}

	}

	/**
	 * @param c the channel
	 * @param authAgent the auth agent
	 * @return see {@link com.trilead.ssh2.Session#requestAuthAgentForwarding(AuthAgentCallback)}
	 * @throws IOException on error
	 */
	public boolean requestChannelAgentForwarding(Channel c, AuthAgentCallback authAgent) throws IOException {
		synchronized (this)
		{
			if (this.authAgent != null)
				throw new IllegalStateException("Auth agent already exists");

			this.authAgent = authAgent;
		}

		synchronized (channels)
		{
			globalSuccessCounter = globalFailedCounter = 0;
		}

		if (log.isEnabled())
			log.log(50, "Requesting agent forwarding");

		PacketChannelAuthAgentReq aar = new PacketChannelAuthAgentReq(c.remoteID);
		tm.sendMessage(aar.getPayload());

		if (!waitForChannelRequestResult(c)) {
			authAgent = null;
			return false;
		}

		return true;
	}

	public void registerThread(IChannelWorkerThread thr) throws IOException
	{
		synchronized (listenerThreads)
		{
			if (!listenerThreadsAllowed)
				throw new IOException("Too late, this connection is closed.");
			listenerThreads.add(thr);
		}
	}

	public Channel openDirectTCPIPChannel(String host_to_connect, int port_to_connect, String originator_IP_address,
			int originator_port) throws IOException
	{
		Channel c = new Channel(this);

		synchronized (c)
		{
			c.localID = addChannel(c);
			// end of synchronized block forces writing out to main memory
		}

		PacketOpenDirectTCPIPChannel dtc = new PacketOpenDirectTCPIPChannel(c.localID, c.localWindow,
				c.localMaxPacketSize, host_to_connect, port_to_connect, originator_IP_address, originator_port);

		tm.sendMessage(dtc.getPayload());

		waitUntilChannelOpen(c);

		return c;
	}

	public Channel openSessionChannel() throws IOException
	{
		return openSessionChannel(Channel.CHANNEL_BUFFER_SIZE);
	}

	/**
	 * @param windowSize the receive window of the new channel, in bytes (see
	 *            {@link Channel#Channel(ChannelManager, int)}).
	 */
	public Channel openSessionChannel(int windowSize) throws IOException
	{
		Channel c = new Channel(this, windowSize);

		synchronized (c)
		{
			c.localID = addChannel(c);
			// end of synchronized block forces the writing out to main memory
		}

		if (log.isEnabled())
			log.log(50, "Sending SSH_MSG_CHANNEL_OPEN (Channel " + c.localID + ")");

		PacketOpenSessionChannel smo = new PacketOpenSessionChannel(c.localID, c.localWindow, c.localMaxPacketSize);
		tm.sendMessage(smo.getPayload());

		waitUntilChannelOpen(c);

		return c;
	}

	public void requestGlobalTrileadPing() throws IOException
	{
		synchronized (channels)
		{
			globalSuccessCounter = globalFailedCounter = 0;
		}

		PacketGlobalTrileadPing pgtp = new PacketGlobalTrileadPing();

		tm.sendMessage(pgtp.getPayload());

		if (log.isEnabled())
			log.log(50, "Sending SSH_MSG_GLOBAL_REQUEST 'trilead-ping'.");

		try
		{
			if (waitForGlobalRequestResult())
				throw new IOException("Your server is alive - but buggy. "
						+ "It replied with SSH_MSG_REQUEST_SUCCESS when it actually should not.");

		}
		catch (IOException e)
		{
			throw new IOException("The ping request failed.", e);
		}
	}

	public void requestChannelTrileadPing(Channel c) throws IOException
	{
		PacketChannelTrileadPing pctp;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot ping this channel (" + c.getReasonClosed() + ")");

			pctp = new PacketChannelTrileadPing(c.remoteID);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot ping this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(pctp.getPayload());
		}

		try
		{
			if (waitForChannelRequestResult(c))
				throw new IOException("Your server is alive - but buggy. "
						+ "It replied with SSH_MSG_SESSION_SUCCESS when it actually should not.");

		}
		catch (IOException e)
		{
			throw new IOException("The ping request failed.", e);
		}
	}

	public void requestPTY(Channel c, String term, int term_width_characters, int term_height_characters,
			int term_width_pixels, int term_height_pixels, byte[] terminal_modes) throws IOException
	{
		PacketSessionPtyRequest spr;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot request PTY on this channel (" + c.getReasonClosed() + ")");

			spr = new PacketSessionPtyRequest(c.remoteID, true, term, term_width_characters, term_height_characters,
					term_width_pixels, term_height_pixels, terminal_modes);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot request PTY on this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(spr.getPayload());
		}

		try
		{
			if (!waitForChannelRequestResult(c))
				throw new IOException("The server denied the request.");
		}
		catch (IOException e)
		{
			throw new IOException("PTY request failed", e);
		}
	}


	public void resizePTY(Channel c, int term_width_characters, int term_height_characters,
			int term_width_pixels, int term_height_pixels) throws IOException {
		PacketSessionPtyResize spr;

		synchronized (c) {
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot request PTY on this channel ("
						+ c.getReasonClosed() + ")");

			spr = new PacketSessionPtyResize(c.remoteID, term_width_characters, term_height_characters,
					term_width_pixels, term_height_pixels);
			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock) {
			if (c.closeMessageSent)
				throw new IOException("Cannot request PTY on this channel ("
						+ c.getReasonClosed() + ")");
			tm.sendMessage(spr.getPayload());
		}
	}


	public void requestX11(Channel c, boolean singleConnection, String x11AuthenticationProtocol,
			String x11AuthenticationCookie, int x11ScreenNumber) throws IOException
	{
		PacketSessionX11Request psr;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot request X11 on this channel (" + c.getReasonClosed() + ")");

			psr = new PacketSessionX11Request(c.remoteID, true, singleConnection, x11AuthenticationProtocol,
					x11AuthenticationCookie, x11ScreenNumber);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot request X11 on this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(psr.getPayload());
		}

		if (log.isEnabled())
			log.log(50, "Requesting X11 forwarding (Channel " + c.localID + "/" + c.remoteID + ")");

		try
		{
			if (!waitForChannelRequestResult(c))
				throw new IOException("The server denied the request.");
		}
		catch (IOException e)
		{
			throw new IOException("The X11 request failed.", e);
		}
	}

	public void requestSubSystem(Channel c, String subSystemName) throws IOException
	{
		PacketSessionSubsystemRequest ssr;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot request subsystem on this channel (" + c.getReasonClosed() + ")");

			ssr = new PacketSessionSubsystemRequest(c.remoteID, true, subSystemName);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot request subsystem on this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(ssr.getPayload());
		}

		try
		{
			if (!waitForChannelRequestResult(c))
				throw new IOException("The server denied the request.");
		}
		catch (IOException e)
		{
			throw new IOException("The subsystem request failed.", e);
		}
	}

	public void requestExecCommand(Channel c, String cmd) throws IOException
	{
		PacketSessionExecCommand sm;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot execute command on this channel (" + c.getReasonClosed() + ")");

			sm = new PacketSessionExecCommand(c.remoteID, true, cmd);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot execute command on this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(sm.getPayload());
		}

		if (log.isEnabled())
			log.log(50, "Executing command (channel " + c.localID + ", '" + cmd + "')");

		try
		{
			if (!waitForChannelRequestResult(c))
				throw new IOException("The server denied the request.");
		}
		catch (IOException e)
		{
			throw new IOException("The execute request failed.", e);
		}
	}

	public void requestShell(Channel c) throws IOException
	{
		PacketSessionStartShell sm;

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Cannot start shell on this channel (" + c.getReasonClosed() + ")");

			sm = new PacketSessionStartShell(c.remoteID, true);

			c.successCounter = c.failedCounter = 0;
		}

		synchronized (c.channelSendLock)
		{
			if (c.closeMessageSent)
				throw new IOException("Cannot start shell on this channel (" + c.getReasonClosed() + ")");
			tm.sendMessage(sm.getPayload());
		}

		try
		{
			if (!waitForChannelRequestResult(c))
				throw new IOException("The server denied the request.");
		}
		catch (IOException e)
		{
			throw new IOException("The shell request failed.", e);
		}
	}

	public void msgChannelExtendedData(byte[] msg, int msglen) throws IOException
	{
		if (msglen <= 13)
			throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);
		int dataType = ((msg[5] & 0xff) << 24) | ((msg[6] & 0xff) << 16) | ((msg[7] & 0xff) << 8) | (msg[8] & 0xff);
		int len = ((msg[9] & 0xff) << 24) | ((msg[10] & 0xff) << 16) | ((msg[11] & 0xff) << 8) | (msg[12] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_EXTENDED_DATA message for non-existent channel " + id);

		if (dataType != Packets.SSH_EXTENDED_DATA_STDERR)
			throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has unknown type (" + dataType + ")");

		if (len != (msglen - 13))
			throw new IOException("SSH_MSG_CHANNEL_EXTENDED_DATA message has wrong len (calculated " + (msglen - 13)
					+ ", got " + len + ")");

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_CHANNEL_EXTENDED_DATA (channel " + id + ", " + len + ")");

		synchronized (c)
		{
			if (c.state == Channel.STATE_CLOSED)
				return; // ignore

			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Got SSH_MSG_CHANNEL_EXTENDED_DATA, but channel is not in correct state ("
						+ c.state + ")");

			if (c.localWindow < len)
				throw new IOException("Remote sent too much data, does not fit into window.");

			c.localWindow -= len;

			System.arraycopy(msg, 13, c.stderrBuffer, c.stderrWritepos, len);
			c.stderrWritepos += len;

			c.notifyAll();
		}
	}

	/**
	 * Wait until for a condition.
	 *
	 * @param c
	 *            Channel
	 * @param timeout
	 *            in ms, 0 means no timeout.
	 * @param condition_mask
	 *            minimum event mask
	 * @return all current events
	 *
	 */
	public int waitForCondition(Channel c, long timeout, int condition_mask)
	{
		long end_time = 0;
		boolean end_time_set = false;

		synchronized (c)
		{
			while (true)
			{
				int current_cond = 0;

				int stdoutAvail = c.stdoutWritepos - c.stdoutReadpos;
				int stderrAvail = c.stderrWritepos - c.stderrReadpos;

				if (stdoutAvail > 0)
					current_cond = current_cond | ChannelCondition.STDOUT_DATA;

				if (stderrAvail > 0)
					current_cond = current_cond | ChannelCondition.STDERR_DATA;

				if (c.EOF)
					current_cond = current_cond | ChannelCondition.EOF;

				if (c.getExitStatus() != null)
					current_cond = current_cond | ChannelCondition.EXIT_STATUS;

				if (c.getExitSignal() != null)
					current_cond = current_cond | ChannelCondition.EXIT_SIGNAL;

				if (c.state == Channel.STATE_CLOSED)
					return current_cond | ChannelCondition.CLOSED | ChannelCondition.EOF;

				if ((current_cond & condition_mask) != 0)
					return current_cond;

				if (timeout > 0)
				{
					if (!end_time_set)
					{
						end_time = System.currentTimeMillis() + timeout;
						end_time_set = true;
					}
					else
					{
						timeout = end_time - System.currentTimeMillis();

						if (timeout <= 0)
							return current_cond | ChannelCondition.TIMEOUT;
					}
				}

				try
				{
					if (timeout > 0)
						c.wait(timeout);
					else
						c.wait();
				}
				catch (InterruptedException e)
				{
				}
			}
		}
	}

	public int getAvailable(Channel c, boolean extended) {
		synchronized (c)
		{
			int avail;

			if (extended)
				avail = c.stderrWritepos - c.stderrReadpos;
			else
				avail = c.stdoutWritepos - c.stdoutReadpos;

			return ((avail > 0) ? avail : (c.EOF ? -1 : 0));
		}
	}

	public int getChannelData(Channel c, boolean extended, byte[] target, int off, int len) throws IOException
	{
		int copylen = 0;
		int increment = 0;
		int remoteID = 0;
		int localID = 0;

		synchronized (c)
		{
			int stdoutAvail = 0;
			int stderrAvail = 0;

			while (true)
			{
				/*
				 * Data available? We have to return remaining data even if the
				 * channel is already closed.
				 */

				stdoutAvail = c.stdoutWritepos - c.stdoutReadpos;
				stderrAvail = c.stderrWritepos - c.stderrReadpos;

				if ((!extended) && (stdoutAvail != 0))
					break;

				if ((extended) && (stderrAvail != 0))
					break;

				/* Do not wait if more data will never arrive (EOF or CLOSED) */

				if ((c.EOF) || (c.state != Channel.STATE_OPEN))
					return -1;

				try
				{
					c.wait();
				}
				catch (InterruptedException ignore)
				{
				}
			}

			/* OK, there is some data. Return it. */

			if (!extended)
			{
				copylen = (stdoutAvail > len) ? len : stdoutAvail;
				System.arraycopy(c.stdoutBuffer, c.stdoutReadpos, target, off, copylen);
				c.stdoutReadpos += copylen;

				if (c.stdoutReadpos != c.stdoutWritepos)

					System.arraycopy(c.stdoutBuffer, c.stdoutReadpos, c.stdoutBuffer, 0, c.stdoutWritepos
							- c.stdoutReadpos);

				c.stdoutWritepos -= c.stdoutReadpos;
				c.stdoutReadpos = 0;
			}
			else
			{
				copylen = (stderrAvail > len) ? len : stderrAvail;
				System.arraycopy(c.stderrBuffer, c.stderrReadpos, target, off, copylen);
				c.stderrReadpos += copylen;

				if (c.stderrReadpos != c.stderrWritepos)

					System.arraycopy(c.stderrBuffer, c.stderrReadpos, c.stderrBuffer, 0, c.stderrWritepos
							- c.stderrReadpos);

				c.stderrWritepos -= c.stderrReadpos;
				c.stderrReadpos = 0;
			}

			if (c.state != Channel.STATE_OPEN)
				return copylen;

			if (c.localWindow < ((c.bufferSize + 1) / 2))
			{
				int minFreeSpace = Math.min(c.bufferSize - c.stdoutWritepos, c.bufferSize - c.stderrWritepos);

				increment = minFreeSpace - c.localWindow;
				c.localWindow = minFreeSpace;
			}

			remoteID = c.remoteID; /* read while holding the lock */
			localID = c.localID; /* read while holding the lock */
		}

		/*
		 * If a consumer reads stdout and stdin in parallel, we may end up with
		 * sending two msgWindowAdjust messages. Luckily, it
		 * does not matter in which order they arrive at the server.
		 */

		if (increment > 0)
		{
			if (log.isEnabled())
				log.log(80, "Sending SSH_MSG_CHANNEL_WINDOW_ADJUST (channel " + localID + ", " + increment + ")");

			synchronized (c.channelSendLock)
			{
				byte[] msg = c.msgWindowAdjust;

				msg[0] = Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST;
				msg[1] = (byte) (remoteID >> 24);
				msg[2] = (byte) (remoteID >> 16);
				msg[3] = (byte) (remoteID >> 8);
				msg[4] = (byte) (remoteID);
				msg[5] = (byte) (increment >> 24);
				msg[6] = (byte) (increment >> 16);
				msg[7] = (byte) (increment >> 8);
				msg[8] = (byte) (increment);

				if (!c.closeMessageSent)
					tm.sendMessage(msg);
			}
		}

		return copylen;
	}

	public void msgChannelData(byte[] msg, int msglen) throws IOException
	{
		if (msglen <= 9)
			throw new IOException("SSH_MSG_CHANNEL_DATA message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);
		int len = ((msg[5] & 0xff) << 24) | ((msg[6] & 0xff) << 16) | ((msg[7] & 0xff) << 8) | (msg[8] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_DATA message for non-existent channel " + id);

		if (len != (msglen - 9))
			throw new IOException("SSH_MSG_CHANNEL_DATA message has wrong len (calculated " + (msglen - 9) + ", got "
					+ len + ")");

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_CHANNEL_DATA (channel " + id + ", " + len + ")");

		synchronized (c)
		{
			if (c.state == Channel.STATE_CLOSED)
				return; // ignore

			if (c.state != Channel.STATE_OPEN)
				throw new IOException("Got SSH_MSG_CHANNEL_DATA, but channel is not in correct state (" + c.state + ")");

			if (c.localWindow < len)
				throw new IOException("Remote sent too much data, does not fit into window.");

			c.localWindow -= len;

			System.arraycopy(msg, 9, c.stdoutBuffer, c.stdoutWritepos, len);
			c.stdoutWritepos += len;

			c.notifyAll();
		}
	}

	public void msgChannelWindowAdjust(byte[] msg, int msglen) throws IOException
	{
		if (msglen != 9)
			throw new IOException("SSH_MSG_CHANNEL_WINDOW_ADJUST message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);
		int windowChange = ((msg[5] & 0xff) << 24) | ((msg[6] & 0xff) << 16) | ((msg[7] & 0xff) << 8) | (msg[8] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_WINDOW_ADJUST message for non-existent channel " + id);

		synchronized (c)
		{
			final long huge = 0xFFFFffffL; /* 2^32 - 1 */

			c.remoteWindow += (windowChange & huge); /* avoid sign extension */

			/* TODO - is this a good heuristic? */

			if ((c.remoteWindow > huge))
				c.remoteWindow = huge;

			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_CHANNEL_WINDOW_ADJUST (channel " + id + ", " + windowChange + ")");
	}

	public void msgChannelOpen(byte[] msg, int msglen) throws IOException
	{
		TypesReader tr = new TypesReader(msg, 0, msglen);

		tr.readByte(); // skip packet type
		String channelType = tr.readString();
		int remoteID = tr.readUINT32(); /* sender channel */
		int remoteWindow = tr.readUINT32(); /* initial window size */
		int remoteMaxPacketSize = tr.readUINT32(); /* maximum packet size */

		if ("x11".equals(channelType))
		{
			synchronized (x11_magic_cookies)
			{
				/* If we did not request X11 forwarding, then simply ignore this bogus request. */

				if (x11_magic_cookies.size() == 0)
				{
					PacketChannelOpenFailure pcof = new PacketChannelOpenFailure(remoteID,
							Packets.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "X11 forwarding not activated", "");

					tm.sendAsynchronousMessage(pcof.getPayload());

					if (log.isEnabled())
						log.log(20, "Unexpected X11 request, denying it!");

					return;
				}
			}

			String remoteOriginatorAddress = tr.readString();
			int remoteOriginatorPort = tr.readUINT32();

			Channel c = new Channel(this);

			synchronized (c)
			{
				c.remoteID = remoteID;
				c.remoteWindow = remoteWindow & 0xFFFFffffL; /* properly convert UINT32 to long */
				c.remoteMaxPacketSize = remoteMaxPacketSize;
				c.localID = addChannel(c);
			}

			/*
			 * The open confirmation message will be sent from another thread
			 */

			RemoteX11AcceptThread rxat = new RemoteX11AcceptThread(c, remoteOriginatorAddress, remoteOriginatorPort);
			rxat.setDaemon(true);
			rxat.start();

			return;
		}

		if ("forwarded-tcpip".equals(channelType))
		{
			String remoteConnectedAddress = tr.readString(); /* address that was connected */
			int remoteConnectedPort = tr.readUINT32(); /* port that was connected */
			String remoteOriginatorAddress = tr.readString(); /* originator IP address */
			int remoteOriginatorPort = tr.readUINT32(); /* originator port */

			RemoteForwardingData rfd = null;

			synchronized (remoteForwardings)
			{
				rfd = remoteForwardings.get(Integer.valueOf(remoteConnectedPort));
			}

			if (rfd == null)
			{
				PacketChannelOpenFailure pcof = new PacketChannelOpenFailure(remoteID,
						Packets.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
						"No thanks, unknown port in forwarded-tcpip request", "");

				/* Always try to be polite. */

				tm.sendAsynchronousMessage(pcof.getPayload());

				if (log.isEnabled())
					log.log(20, "Unexpected forwarded-tcpip request, denying it!");

				return;
			}

			Channel c = new Channel(this);

			synchronized (c)
			{
				c.remoteID = remoteID;
				c.remoteWindow = remoteWindow & 0xFFFFffffL; /* convert UINT32 to long */
				c.remoteMaxPacketSize = remoteMaxPacketSize;
				c.localID = addChannel(c);
			}

			/*
			 * The open confirmation message will be sent from another thread.
			 */

			RemoteAcceptThread rat = new RemoteAcceptThread(c, remoteConnectedAddress, remoteConnectedPort,
					remoteOriginatorAddress, remoteOriginatorPort, rfd.targetAddress, rfd.targetPort);

			rat.setDaemon(true);
			rat.start();

			return;
		}

		if ("auth-agent@openssh.com".equals(channelType)) {
			Channel c = new Channel(this);

			synchronized (c)
			{
				c.remoteID = remoteID;
				c.remoteWindow = remoteWindow & 0xFFFFffffL; /* properly convert UINT32 to long */
				c.remoteMaxPacketSize = remoteMaxPacketSize;
				c.localID = addChannel(c);
			}

			AuthAgentForwardThread aat = new AuthAgentForwardThread(c, authAgent);

			aat.setDaemon(true);
			aat.start();

			return;
		}

		/* Tell the server that we have no idea what it is talking about */

		PacketChannelOpenFailure pcof = new PacketChannelOpenFailure(remoteID, Packets.SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
				"Unknown channel type", "");

		tm.sendAsynchronousMessage(pcof.getPayload());

		if (log.isEnabled())
			log.log(20, "The peer tried to open an unsupported channel type (" + channelType + ")");
	}

	public void msgChannelRequest(byte[] msg, int msglen) throws IOException
	{
		TypesReader tr = new TypesReader(msg, 0, msglen);

		tr.readByte(); // skip packet type
		int id = tr.readUINT32();

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_REQUEST message for non-existent channel " + id);

		String type = tr.readString("US-ASCII");
		boolean wantReply = tr.readBoolean();

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_CHANNEL_REQUEST (channel " + id + ", '" + type + "')");

		if (type.equals("exit-status"))
		{
			if (wantReply)
				throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message, 'want reply' is true");

			int exit_status = tr.readUINT32();

			if (tr.remain() != 0)
				throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");

			synchronized (c)
			{
				c.exit_status = Integer.valueOf(exit_status);
				c.notifyAll();
			}

			if (log.isEnabled())
				log.log(50, "Got EXIT STATUS (channel " + id + ", status " + exit_status + ")");

			return;
		}

		if (type.equals("exit-signal"))
		{
			if (wantReply)
				throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message, 'want reply' is true");

			String signame = tr.readString("US-ASCII");
			tr.readBoolean();
			tr.readString();
			tr.readString();

			if (tr.remain() != 0)
				throw new IOException("Badly formatted SSH_MSG_CHANNEL_REQUEST message");

			synchronized (c)
			{
				c.exit_signal = signame;
				c.notifyAll();
			}

			if (log.isEnabled())
				log.log(50, "Got EXIT SIGNAL (channel " + id + ", signal " + signame + ")");

			return;
		}

		/* We simply ignore unknown channel requests, however, if the server wants a reply,
		 * then we signal that we have no idea what it is about.
		 */

		if (wantReply)
		{
			byte[] reply = new byte[5];

			reply[0] = Packets.SSH_MSG_CHANNEL_FAILURE;
			reply[1] = (byte) (c.remoteID >> 24);
			reply[2] = (byte) (c.remoteID >> 16);
			reply[3] = (byte) (c.remoteID >> 8);
			reply[4] = (byte) (c.remoteID);

			tm.sendAsynchronousMessage(reply);
		}

		if (log.isEnabled())
			log.log(50, "Channel request '" + type + "' is not known, ignoring it");
	}

	public void msgChannelEOF(byte[] msg, int msglen) throws IOException
	{
		if (msglen != 5)
			throw new IOException("SSH_MSG_CHANNEL_EOF message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_EOF message for non-existent channel " + id);

		synchronized (c)
		{
			c.EOF = true;
			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(50, "Got SSH_MSG_CHANNEL_EOF (channel " + id + ")");
	}

	public void msgChannelClose(byte[] msg, int msglen) throws IOException
	{
		if (msglen != 5)
			throw new IOException("SSH_MSG_CHANNEL_CLOSE message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_CLOSE message for non-existent channel " + id);

		synchronized (c)
		{
			c.EOF = true;
			c.state = Channel.STATE_CLOSED;
			c.setReasonClosed("Close requested by remote");
			c.closeMessageRecv = true;

			removeChannel(c.localID);

			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(50, "Got SSH_MSG_CHANNEL_CLOSE (channel " + id + ")");
	}

	public void msgChannelSuccess(byte[] msg, int msglen) throws IOException
	{
		if (msglen != 5)
			throw new IOException("SSH_MSG_CHANNEL_SUCCESS message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_SUCCESS message for non-existent channel " + id);

		synchronized (c)
		{
			c.successCounter++;
			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_CHANNEL_SUCCESS (channel " + id + ")");
	}

	public void msgChannelFailure(byte[] msg, int msglen) throws IOException
	{
		if (msglen != 5)
			throw new IOException("SSH_MSG_CHANNEL_FAILURE message has wrong size (" + msglen + ")");

		int id = ((msg[1] & 0xff) << 24) | ((msg[2] & 0xff) << 16) | ((msg[3] & 0xff) << 8) | (msg[4] & 0xff);

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_FAILURE message for non-existent channel " + id);

		synchronized (c)
		{
			c.failedCounter++;
			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(50, "Got SSH_MSG_CHANNEL_FAILURE (channel " + id + ")");
	}

	public void msgChannelOpenConfirmation(byte[] msg, int msglen) throws IOException
	{
		PacketChannelOpenConfirmation sm = new PacketChannelOpenConfirmation(msg, 0, msglen);

		Channel c = getChannel(sm.recipientChannelID);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION message for non-existent channel "
					+ sm.recipientChannelID);

		synchronized (c)
		{
			if (c.state != Channel.STATE_OPENING)
				throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_CONFIRMATION message for channel "
						+ sm.recipientChannelID);

			c.remoteID = sm.senderChannelID;
			c.remoteWindow = sm.initialWindowSize & 0xFFFFffffL; /* convert UINT32 to long */
			c.remoteMaxPacketSize = sm.maxPacketSize;
			c.state = Channel.STATE_OPEN;
			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(50, "Got SSH_MSG_CHANNEL_OPEN_CONFIRMATION (channel " + sm.recipientChannelID + " / remote: "
					+ sm.senderChannelID + ")");
	}

	public void msgChannelOpenFailure(byte[] msg, int msglen) throws IOException
	{
		if (msglen < 5)
			throw new IOException("SSH_MSG_CHANNEL_OPEN_FAILURE message has wrong size (" + msglen + ")");

		TypesReader tr = new TypesReader(msg, 0, msglen);

		tr.readByte(); // skip packet type
		int id = tr.readUINT32(); /* sender channel */

		Channel c = getChannel(id);

		if (c == null)
			throw new IOException("Unexpected SSH_MSG_CHANNEL_OPEN_FAILURE message for non-existent channel " + id);

		int reasonCode = tr.readUINT32();
		String description = tr.readString("UTF-8");

		String reasonCodeSymbolicName = null;

		switch (reasonCode)
		{
		case 1:
			reasonCodeSymbolicName = "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED";
			break;
		case 2:
			reasonCodeSymbolicName = "SSH_OPEN_CONNECT_FAILED";
			break;
		case 3:
			reasonCodeSymbolicName = "SSH_OPEN_UNKNOWN_CHANNEL_TYPE";
			break;
		case 4:
			reasonCodeSymbolicName = "SSH_OPEN_RESOURCE_SHORTAGE";
			break;
		default:
			reasonCodeSymbolicName = "UNKNOWN REASON CODE (" + reasonCode + ")";
		}

		StringBuilder descriptionBuffer = new StringBuilder();
		descriptionBuffer.append(description);

		for (int i = 0; i < descriptionBuffer.length(); i++)
		{
			char cc = descriptionBuffer.charAt(i);

			if ((cc >= 32) && (cc <= 126))
				continue;
			descriptionBuffer.setCharAt(i, '\uFFFD');
		}

		synchronized (c)
		{
			c.EOF = true;
			c.state = Channel.STATE_CLOSED;
			c.setReasonClosed("The server refused to open the channel (" + reasonCodeSymbolicName + ", '"
					+ descriptionBuffer.toString() + "')");
			c.notifyAll();
		}

		if (log.isEnabled())
			log.log(50, "Got SSH_MSG_CHANNEL_OPEN_FAILURE (channel " + id + ")");
	}

	public void msgGlobalRequest(byte[] msg, int msglen) throws IOException
	{
		TypesReader tr = new TypesReader(msg, 0, msglen);

		tr.readByte(); // skip packet type
		String requestName = tr.readString();
		boolean wantReply = tr.readBoolean();

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_GLOBAL_REQUEST (" + requestName + ")");

		if (PacketGlobalHostkeys.HOSTKEYS_VENDOR.equals(requestName) ||
				PacketGlobalHostkeys.HOSTKEYS_STANDARD.equals(requestName)) {
			try {
				PacketGlobalHostkeys hostkeys = new PacketGlobalHostkeys(msg, 0, msglen);
				processHostkeysAdvertisement(hostkeys, requestName);
			} catch (Exception e) {
				if (log.isEnabled())
					log.log(20, "Failed to process hostkeys advertisement: " + e.getMessage());
			}
			// hostkeys-00@openssh.com typically has wantReply=false, but if the
			// server does request a reply, acknowledge it since we processed it.
			if (wantReply)
			{
				byte[] reply_success = new byte[1];
				reply_success[0] = Packets.SSH_MSG_REQUEST_SUCCESS;
				tm.sendAsynchronousMessage(reply_success);
			}
			return;
		}

		if (wantReply)
		{
			byte[] reply_failure = new byte[1];
			reply_failure[0] = Packets.SSH_MSG_REQUEST_FAILURE;

			tm.sendAsynchronousMessage(reply_failure);
		}
	}

	public void msgGlobalSuccess(byte[] msg, int msglen) throws IOException {
		// Check for pending hostkeys-prove BEFORE incrementing the global counter,
		// so the hostkeys-prove response doesn't interfere with other global request tracking.
		synchronized (hostkeysProveLock) {
			if (pendingHostkeysProve != null && !pendingHostkeysProve.completed) {
				try {
					PacketGlobalHostkeysProve response =
						new PacketGlobalHostkeysProve(msg, 0, msglen, true);

					pendingHostkeysProve.responseSignatures = response.getSignatures();
					pendingHostkeysProve.succeeded = true;
					pendingHostkeysProve.completed = true;

					processHostkeysProveResponse(pendingHostkeysProve);
				} catch (IOException e) {
					if (log.isEnabled())
						log.log(20, "Failed to parse hostkeys-prove response: " + e.getMessage());
					pendingHostkeysProve.completed = true;
					pendingHostkeysProve.succeeded = false;
				} finally {
					hostkeysProveLock.notifyAll();
				}
				return;
			}
		}

		synchronized (channels)
		{
			globalSuccessCounter++;
			channels.notifyAll();
		}

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_REQUEST_SUCCESS");
	}

	public void msgGlobalFailure() {
		synchronized (channels)
		{
			globalFailedCounter++;
			channels.notifyAll();
		}

		synchronized (hostkeysProveLock) {
			if (pendingHostkeysProve != null && !pendingHostkeysProve.completed) {
				pendingHostkeysProve.completed = true;
				pendingHostkeysProve.succeeded = false;
				hostkeysProveLock.notifyAll();

				if (log.isEnabled())
					log.log(50, "Server refused hostkeys-prove request");

				pendingHostkeysProve = null;
				return;
			}
		}

		if (log.isEnabled())
			log.log(80, "Got SSH_MSG_REQUEST_FAILURE");
	}

	public void handleMessage(byte[] msg, int msglen) throws IOException
	{
		if (msg == null)
		{
			if (log.isEnabled())
				log.log(50, "HandleMessage: got shutdown");

			synchronized (listenerThreads)
			{
				for (IChannelWorkerThread lat : listenerThreads)
				{
					lat.stopWorking();
				}
				listenerThreadsAllowed = false;
			}

			synchronized (channels)
			{
				shutdown = true;

				for (Channel c : channels)
				{
					synchronized (c)
					{
						c.EOF = true;
						c.state = Channel.STATE_CLOSED;
						c.setReasonClosed("The connection is being shutdown");
						c.closeMessageRecv = true; /*
																															 * You never know, perhaps
																															 * we are waiting for a
																															 * pending close message
																															 * from the server...
																															 */
						c.notifyAll();
					}
				}
				/* Works with J2ME */
				channels.clear();
				channels.notifyAll(); /* Notify global response waiters */
				return;
			}
		}

		switch (msg[0])
		{
		case Packets.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
			msgChannelOpenConfirmation(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST:
			msgChannelWindowAdjust(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_DATA:
			msgChannelData(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_EXTENDED_DATA:
			msgChannelExtendedData(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_REQUEST:
			msgChannelRequest(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_EOF:
			msgChannelEOF(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_OPEN:
			msgChannelOpen(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_CLOSE:
			msgChannelClose(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_SUCCESS:
			msgChannelSuccess(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_FAILURE:
			msgChannelFailure(msg, msglen);
			break;
		case Packets.SSH_MSG_CHANNEL_OPEN_FAILURE:
			msgChannelOpenFailure(msg, msglen);
			break;
		case Packets.SSH_MSG_GLOBAL_REQUEST:
			msgGlobalRequest(msg, msglen);
			break;
		case Packets.SSH_MSG_REQUEST_SUCCESS:
			msgGlobalSuccess(msg, msglen);
			break;
		case Packets.SSH_MSG_REQUEST_FAILURE:
			msgGlobalFailure();
			break;
		default:
			throw new IOException("Cannot handle unknown channel message " + (msg[0] & 0xff));
		}
	}

	private void processHostkeysAdvertisement(PacketGlobalHostkeys hostkeys, String requestName) throws IOException
	{
		ServerHostKeyVerifier verifier = tm.getServerHostKeyVerifier();
		if (!(verifier instanceof ExtendedServerHostKeyVerifier)) {
			if (log.isEnabled())
				log.log(50, "Received hostkeys but verifier doesn't extend ExtendedServerHostKeyVerifier");
			return;
		}

		ExtendedServerHostKeyVerifier extVerifier = (ExtendedServerHostKeyVerifier) verifier;
		String hostname = tm.getHostname();
		int port = tm.getPort();

		List<byte[]> advertisedKeys = hostkeys.getHostkeys();

		if (advertisedKeys.size() > MAX_ADVERTISED_HOSTKEYS) {
			if (log.isEnabled())
				log.log(20, "Server advertised too many keys: " + advertisedKeys.size());
			return;
		}

		List<String> knownAlgos = extVerifier.getKnownKeyAlgorithmsForHost(hostname, port);

		// Normalize algorithm names so RSA signature variants (rsa-sha2-256,
		// rsa-sha2-512) are treated as the same key type as ssh-rsa.
		Set<String> normalizedKnownAlgoSet = new HashSet<>();
		if (knownAlgos != null) {
			for (String algo : knownAlgos) {
				normalizedKnownAlgoSet.add(normalizeKeyAlgorithm(algo));
			}
		}

		List<byte[]> newKeys = new ArrayList<>();
		Set<String> normalizedAdvertisedAlgoSet = new HashSet<>();

		for (byte[] keyBlob : advertisedKeys) {
			String keyAlgo = extractKeyAlgorithm(keyBlob);
			if (keyAlgo == null)
				continue;

			String normalizedAlgo = normalizeKeyAlgorithm(keyAlgo);
			normalizedAdvertisedAlgoSet.add(normalizedAlgo);

			if (!normalizedKnownAlgoSet.contains(normalizedAlgo)) {
				newKeys.add(keyBlob);
			}
		}

		if (knownAlgos != null) {
			for (String knownAlgo : knownAlgos) {
				if (knownAlgo == null)
					continue;
				if (!normalizedAdvertisedAlgoSet.contains(normalizeKeyAlgorithm(knownAlgo))) {
					extVerifier.removeServerHostKey(hostname, port, knownAlgo, null);
					if (log.isEnabled())
						log.log(50, "Removed hostkey algorithm no longer advertised: " + knownAlgo);
				}
			}
		}

		if (!newKeys.isEmpty()) {
			if (log.isEnabled())
				log.log(50, "Server advertised " + newKeys.size() + " new hostkey(s)");
			requestHostkeysProve(newKeys, requestName, hostname, port);
		}
	}

	private void requestHostkeysProve(List<byte[]> newKeys, String hostkeysRequestName,
									String hostname, int port) throws IOException
	{
		String proveRequestName;
		if (PacketGlobalHostkeys.HOSTKEYS_STANDARD.equals(hostkeysRequestName)) {
			proveRequestName = PacketGlobalHostkeysProve.HOSTKEYS_PROVE_STANDARD;
		} else {
			proveRequestName = PacketGlobalHostkeysProve.HOSTKEYS_PROVE_VENDOR;
		}

		ConnectionInfo connInfo = tm.getConnectionInfo(1);
		List<byte[]> keysToProve = filterRSAKeys(newKeys, connInfo.serverHostKeyAlgorithm);

		if (keysToProve.isEmpty()) {
			if (log.isEnabled())
				log.log(50, "No keys to prove after RSA filtering");
			return;
		}

		if (keysToProve.size() > MAX_KEYS_TO_PROVE) {
			if (log.isEnabled())
				log.log(20, "Too many keys to prove, limiting to " + MAX_KEYS_TO_PROVE);
			keysToProve = keysToProve.subList(0, MAX_KEYS_TO_PROVE);
		}

		synchronized (hostkeysProveLock) {
			if (pendingHostkeysProve != null) {
				if (log.isEnabled())
					log.log(20, "Hostkeys-prove request already pending, ignoring new request");
				return;
			}
			pendingHostkeysProve = new HostkeysProveRequest(keysToProve, proveRequestName,
															hostname, port);
		}

		PacketGlobalHostkeysProve provePacket = new PacketGlobalHostkeysProve(proveRequestName, keysToProve);
		tm.sendMessage(provePacket.getPayload());

		if (log.isEnabled())
			log.log(50, "Sent " + proveRequestName + " request for " + keysToProve.size() + " keys");
	}

	private List<byte[]> filterRSAKeys(List<byte[]> keys, String negotiatedHostKeyAlgo) throws IOException
	{
		List<byte[]> filtered = new ArrayList<>();

		for (byte[] keyBlob : keys) {
			String keyAlgo = extractKeyAlgorithm(keyBlob);

			if (RSASHA1Verify.ID_SSH_RSA.equals(keyAlgo) ||
				RSASHA256Verify.ID_RSA_SHA_2_256.equals(keyAlgo) ||
				RSASHA512Verify.ID_RSA_SHA_2_512.equals(keyAlgo)) {

				if (RSASHA1Verify.ID_SSH_RSA.equals(negotiatedHostKeyAlgo)) {
					if (log.isEnabled())
						log.log(50, "Skipping RSA key because ssh-rsa was negotiated");
					continue;
				}
			}

			filtered.add(keyBlob);
		}

		return filtered;
	}

	private void processHostkeysProveResponse(final HostkeysProveRequest request)
	{
		Thread processor = new Thread(new Runnable() {
			public void run() {
				processHostkeysProveResponseImpl(request);
			}
		}, "HostkeysProve-Processor");
		processor.setDaemon(true);
		processor.start();
	}

	private void processHostkeysProveResponseImpl(HostkeysProveRequest request)
	{
		try {
			List<byte[]> signatures = request.responseSignatures;
			List<byte[]> requestedKeys = request.requestedKeys;

			if (signatures.size() != requestedKeys.size()) {
				if (log.isEnabled())
					log.log(20, "Signature count mismatch: expected " + requestedKeys.size() +
								" but got " + signatures.size());
				return;
			}

			byte[] sessionId = tm.getSessionIdentifier();
			ServerHostKeyVerifier verifier = tm.getServerHostKeyVerifier();

			if (!(verifier instanceof ExtendedServerHostKeyVerifier)) {
				if (log.isEnabled())
					log.log(20, "Verifier is not ExtendedServerHostKeyVerifier, cannot add keys");
				return;
			}

			ExtendedServerHostKeyVerifier extVerifier = (ExtendedServerHostKeyVerifier) verifier;

			for (int i = 0; i < requestedKeys.size(); i++) {
				byte[] hostkey = requestedKeys.get(i);
				byte[] signature = signatures.get(i);

				if (verifyHostkeyProof(hostkey, signature, sessionId, request.requestName)) {
					String keyAlgo = extractKeyAlgorithm(hostkey);
					extVerifier.addServerHostKey(request.hostname, request.port, keyAlgo, hostkey);

					if (log.isEnabled())
						log.log(50, "Verified and added hostkey: " + keyAlgo);
				} else {
					if (log.isEnabled())
						log.log(20, "Failed to verify hostkey proof for key " + i);
				}
			}
		} catch (Exception e) {
			if (log.isEnabled())
				log.log(20, "Error processing hostkeys-prove response: " + e.getMessage());
		} finally {
			synchronized (hostkeysProveLock) {
				pendingHostkeysProve = null;
			}
		}
	}

	private String extractKeyAlgorithm(byte[] keyBlob) throws IOException
	{
		TypesReader tr = new TypesReader(keyBlob);
		return tr.readString();
	}

	/**
	 * Normalizes RSA algorithm variants to a canonical form for comparison.
	 * In SSH, rsa-sha2-256 and rsa-sha2-512 use the same RSA key as ssh-rsa
	 * (the difference is only the signature hash algorithm). Key blobs always
	 * identify as ssh-rsa regardless of which signature algorithm was negotiated.
	 */
	static String normalizeKeyAlgorithm(String algorithm)
	{
		if (RSASHA256Verify.ID_RSA_SHA_2_256.equals(algorithm) ||
			RSASHA512Verify.ID_RSA_SHA_2_512.equals(algorithm)) {
			return RSASHA1Verify.ID_SSH_RSA;
		}
		return algorithm;
	}

	private SSHSignature getSignatureVerifier(String algorithm)
	{
		if (RSASHA1Verify.ID_SSH_RSA.equals(algorithm))
			return RSASHA1Verify.get();
		if (RSASHA256Verify.ID_RSA_SHA_2_256.equals(algorithm))
			return RSASHA256Verify.get();
		if (RSASHA512Verify.ID_RSA_SHA_2_512.equals(algorithm))
			return RSASHA512Verify.get();
		if (DSASHA1Verify.ID_SSH_DSS.equals(algorithm))
			return DSASHA1Verify.get();
		if (Ed25519Verify.ED25519_ID.equals(algorithm))
			return Ed25519Verify.get();

		if (algorithm.startsWith(ECDSASHA2Verify.ECDSA_SHA2_PREFIX)) {
			if (ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getKeyFormat().equals(algorithm))
				return ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get();
			if (ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().getKeyFormat().equals(algorithm))
				return ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get();
			if (ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().getKeyFormat().equals(algorithm))
				return ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get();
		}

		return null;
	}

	private boolean verifyHostkeyProof(byte[] hostkey, byte[] signature, byte[] sessionId, String requestName) throws IOException
	{
		String keyAlgo = extractKeyAlgorithm(hostkey);

		TypesWriter signedData = new TypesWriter();
		signedData.writeString(requestName);
		signedData.writeString(sessionId, 0, sessionId.length);
		signedData.writeString(hostkey, 0, hostkey.length);
		byte[] dataToVerify = signedData.getBytes();

		SSHSignature verifier = getSignatureVerifier(keyAlgo);
		if (verifier == null) {
			if (log.isEnabled())
				log.log(20, "No signature verifier for algorithm: " + keyAlgo);
			return false;
		}

		PublicKey publicKey = verifier.decodePublicKey(hostkey);
		return verifier.verifySignature(dataToVerify, signature, publicKey);
	}
}
