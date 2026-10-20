
package com.trilead.ssh2;

/**
 * Allow the caller to restrict the IP version of the connection to
 * be established.
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */
@Deprecated
public enum IpVersion {
	IPV4_AND_IPV6,
	IPV4_ONLY,
	IPV6_ONLY
}
