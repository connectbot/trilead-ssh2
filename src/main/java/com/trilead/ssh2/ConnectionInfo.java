
package com.trilead.ssh2;

import java.net.InetSocketAddress;

/**
 * In most cases you probably do not need the information contained in here.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: ConnectionInfo.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */
@Deprecated
public class ConnectionInfo
{
	/**
	 * The address of the local socket.
	 */
	public InetSocketAddress localSocketAddress;

	/**
	 * The address of the remote socket.
	 */
	public InetSocketAddress remoteSocketAddress;

	/**
	 * The used key exchange (KEX) algorithm in the latest key exchange.
	 */
	public String keyExchangeAlgorithm;

	/**
	 * The currently used crypto algorithm for packets from to the client to the
	 * server.
	 */
	public String clientToServerCryptoAlgorithm;
	/**
	 * The currently used crypto algorithm for packets from to the server to the
	 * client.
	 */
	public String serverToClientCryptoAlgorithm;

	/**
	 * The currently used MAC algorithm for packets from to the client to the
	 * server.
	 */
	public String clientToServerMACAlgorithm;
	/**
	 * The currently used MAC algorithm for packets from to the server to the
	 * client.
	 */
	public String serverToClientMACAlgorithm;

	/**
	 * The type of the server host key (currently either "ssh-dss" or
	 * "ssh-rsa").
	 */
	public String serverHostKeyAlgorithm;
	/**
	 * The server host key that was sent during the latest key exchange.
	 */
	public byte[] serverHostKey;

	/**
	 * Number of kex exchanges performed on this connection so far.
	 */
	public int keyExchangeCounter = 0;

	/**
	 * The currently used compression algorithm for packets from the client to
	 * the server.
	 */
	public String clientToServerCompressionAlgorithm;

	/**
	 * The currently used compression algorithm for packets from the server to
	 * the client.
	 */
	public String serverToClientCompressionAlgorithm;
}
