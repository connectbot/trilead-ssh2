package com.trilead.ssh2;

import java.security.KeyPair;
import java.util.Map;

/**
 * AuthAgentCallback.
 *
 * @author Kenny Root
 * @version $Id$
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */
@Deprecated
public interface AuthAgentCallback {

	/**
	 * @return array of blobs containing the OpenSSH-format encoded public keys
	 */
	Map<String, byte[]> retrieveIdentities();

	/**
	 * @param pair A <code>RSAPrivateKey</code>, <code>ECPrivateKey</code>, or
	 *             <code>DSAPrivateKey</code> containing a DSA, EC, or RSA private
	 *             and corresponding <code>PublicKey</code>.
	 * @param comment comment associated with this key
	 * @param confirmUse whether to prompt before using this key
	 * @param lifetime lifetime in seconds for key to be remembered
	 * @return success or failure
	 */
	boolean addIdentity(KeyPair pair, String comment, boolean confirmUse, int lifetime);

	/**
	 * @param publicKey byte blob containing the OpenSSH-format encoded public key
	 * @return success or failure
	 */
	boolean removeIdentity(byte[] publicKey);

	/**
	 * @return success or failure
	 */
	boolean removeAllIdentities();

	/**
	 * @param publicKey byte blob containing the OpenSSH-format encoded public key
	 * @return A <code>RSAPrivateKey</code> or <code>DSAPrivateKey</code>
	 *         containing a DSA or RSA private key of
	 *         the user in Trilead object format.
	 */
	KeyPair getKeyPair(byte[] publicKey);

	/**
	 * @return true if the agent is locked
	 */
	boolean isAgentLocked();

	/**
	 * @param lockPassphrase the passphrase to lock the agent with
	 * @return true if the agent was locked
	 */
	boolean setAgentLock(String lockPassphrase);

	/**
	 * @param unlockPassphrase the passphrase to unlock the agent with
	 * @return true if the agent was unlocked
	 */
	boolean requestAgentUnlock(String unlockPassphrase);
}
