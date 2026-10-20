
package com.trilead.ssh2;

import java.io.IOException;
import java.net.Socket;

/**
 * An abstract interface implemented by all proxy data implementations.
 *
 * @see HTTPProxyData
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: ProxyData.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */

@Deprecated
public interface ProxyData
{
	/**
	 * Connects the socket to the given destination using the proxy method that this instance
	 * represents.
	 * @param hostname hostname of end host (not proxy)
	 * @param port port of end host (not proxy)
	 * @param connectTimeout number of seconds before giving up on connecting to end host
	 * @throws IOException if the connection could not be completed
	 * @return connected socket instance
	 */
	Socket openConnection(String hostname, int port, int connectTimeout) throws IOException;
}
