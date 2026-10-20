package com.trilead.ssh2;

import com.trilead.ssh2.packets.PacketExtInfo;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * SSH extensions reported by the server
 *
 * https://tools.ietf.org/html/draft-ietf-curdle-ssh-ext-info-15
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */
@Deprecated
public class ExtensionInfo
{
	private final Set<String> signatureAlgorithmsAccepted;

	/**
	 * @return Signature algorithms that server will accept. If empty, this extension was absent.
	 */
	public Set<String> getSignatureAlgorithmsAccepted()
	{
		return signatureAlgorithmsAccepted;
	}

	public static ExtensionInfo fromPacketExtInfo(PacketExtInfo packetExtInfo)
	{
		String rawAlgs = packetExtInfo.getExtNameToValue().get("server-sig-algs");
		if (rawAlgs == null)
		{
			return new ExtensionInfo(Collections.<String>emptySet());
		}

		Set<String> algsSet = new HashSet<>();
		Collections.addAll(algsSet, rawAlgs.split(","));
		return new ExtensionInfo(algsSet);
	}

	public static ExtensionInfo noExtInfoSeen()
	{
		return new ExtensionInfo(Collections.<String>emptySet());
	}

	private ExtensionInfo(Set<String> signatureAlgorithmsAccepted)
	{
		this.signatureAlgorithmsAccepted = Collections.unmodifiableSet(signatureAlgorithmsAccepted);
	}
}
