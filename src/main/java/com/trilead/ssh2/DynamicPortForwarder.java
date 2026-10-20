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

package com.trilead.ssh2;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.trilead.ssh2.channel.ChannelManager;
import com.trilead.ssh2.channel.DynamicAcceptThread;

/**
 * A <code>DynamicPortForwarder</code> forwards TCP/IP connections to a local
 * port via the secure tunnel to another host which is selected via the
 * SOCKS protocol. Checkout {@link Connection#createDynamicPortForwarder(int)}
 * on how to create one.
 *
 * @author Kenny Root
 * @version $Id: $
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */
@Deprecated
public class DynamicPortForwarder {
	ChannelManager cm;

	DynamicAcceptThread dat;

	DynamicPortForwarder(ChannelManager cm, int local_port)
			throws IOException
	{
		this.cm = cm;

		dat = new DynamicAcceptThread(cm, local_port);
		dat.setDaemon(true);
		dat.start();
	}

	DynamicPortForwarder(ChannelManager cm, InetSocketAddress addr) throws IOException {
		this.cm = cm;

		dat = new DynamicAcceptThread(cm, addr);
		dat.setDaemon(true);
		dat.start();
	}

	/**
	 * Stop TCP/IP forwarding of newly arriving connections.
	 *
	 */
	public void close() {
		dat.stopWorking();
	}
}
