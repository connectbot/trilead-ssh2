
package com.trilead.ssh2;

import java.io.BufferedReader;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.fingerprint.KeyFingerprint;
import com.trilead.ssh2.crypto.keys.Ed25519PublicKey;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.RSASHA256Verify;
import com.trilead.ssh2.signature.RSASHA512Verify;
import com.trilead.ssh2.transport.KexManager;

/**
 * The <code>KnownHosts</code> class is a handy tool to verify received server hostkeys
 * based on the information in <code>known_hosts</code> files (the ones used by OpenSSH).
 * <p>
 * It offers basically an in-memory database for known_hosts entries, as well as some
 * helper functions. Entries from a <code>known_hosts</code> file can be loaded at construction time.
 * It is also possible to add more keys later (e.g., one can parse different
 * <code>known_hosts</code> files).
 * <p>
 * It is a thread safe implementation, therefore, you need only to instantiate one
 * <code>KnownHosts</code> for your whole application.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: KnownHosts.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */

@Deprecated
public class KnownHosts extends ExtendedServerHostKeyVerifier
{
	public static final int HOSTKEY_IS_OK = 0;
	public static final int HOSTKEY_IS_NEW = 1;
	public static final int HOSTKEY_HAS_CHANGED = 2;

	protected class KnownHostsEntry
	{
		String[] patterns;
		PublicKey key;

		KnownHostsEntry(String[] patterns, PublicKey key)
		{
			this.patterns = patterns;
			this.key = key;
		}

		@Override
		public String toString() {
			return "KnownHostsEntry{keyType=" + key.getAlgorithm() + "}";
		}
	}

	protected final LinkedList<KnownHostsEntry> publicKeys = new LinkedList<>();

	public KnownHosts()
	{
	}

	public KnownHosts(char[] knownHostsData) throws IOException
	{
		initialize(knownHostsData);
	}

	public KnownHosts(File knownHosts) throws IOException
	{
		initialize(knownHosts);
	}

	/**
	 * Adds a single public key entry to the database. Note: this will NOT add the public key
	 * to any physical file (e.g., "~/.ssh/known_hosts") - use <code>addHostkeyToFile()</code> for that purpose.
	 * This method is designed to be used in a {@link ServerHostKeyVerifier}.
	 *
	 * @param hostnames a list of hostname patterns - at least one most be specified. Check out the
	 *        OpenSSH sshd man page for a description of the pattern matching algorithm.
	 * @param serverHostKeyAlgorithm as passed to the {@link ServerHostKeyVerifier}.
	 * @param serverHostKey as passed to the {@link ServerHostKeyVerifier}.
	 * @throws IOException on error
	 */
	public void addHostkey(String[] hostnames, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException
	{
		if (hostnames == null)
			throw new IllegalArgumentException("hostnames may not be null");

		if (RSASHA1Verify.ID_SSH_RSA.equals(serverHostKeyAlgorithm) ||
			RSASHA512Verify.ID_RSA_SHA_2_512.equals(serverHostKeyAlgorithm) ||
			RSASHA256Verify.ID_RSA_SHA_2_256.equals(serverHostKeyAlgorithm))
		{
			PublicKey rpk = RSASHA1Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, rpk));
			}
		} else if (serverHostKeyAlgorithm.equals(DSASHA1Verify.ID_SSH_DSS)) {
			PublicKey dpk = DSASHA1Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, dpk));
			}
		} else if (serverHostKeyAlgorithm.equals(ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getKeyFormat())) {
			PublicKey epk = ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, epk));
			}
		} else if (serverHostKeyAlgorithm.equals(ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().getKeyFormat())) {
			PublicKey epk = ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, epk));
			}
		} else if (serverHostKeyAlgorithm.equals(ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().getKeyFormat())) {
			PublicKey epk = ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, epk));
			}
		} else if (Ed25519Verify.ED25519_ID.equals(serverHostKeyAlgorithm)) {
			PublicKey edpk = Ed25519Verify.get().decodePublicKey(serverHostKey);

			synchronized (publicKeys)
			{
				publicKeys.add(new KnownHostsEntry(hostnames, edpk));
			}
		} else {
			throw new IOException("Unknown host key type (" + serverHostKeyAlgorithm + ")");
		}
	}

	/**
	 * Parses the given known_hosts data and adds entries to the database.
	 *
	 * @param knownHostsData known hosts in textual format
	 * @throws IOException on error
	 */
	public void addHostkeys(char[] knownHostsData) throws IOException
	{
		initialize(knownHostsData);
	}

	/**
	 * Parses the given known_hosts file and adds entries to the database.
	 *
	 * @param knownHosts known hosts file in textual format
	 * @throws IOException on error
	 */
	public void addHostkeys(File knownHosts) throws IOException
	{
		initialize(knownHosts);
	}

	/**
	 * Generate the hashed representation of the given hostname. Useful for adding entries
	 * with hashed hostnames to a known_hosts file. (see -H option of OpenSSH key-gen).
	 *
	 * @param hostname the hostname to hash
	 * @return the hashed representation, e.g., "|1|cDhrv7zwEUV3k71CEPHnhHZezhA=|Xo+2y6rUXo2OIWRAYhBOIijbJMA="
	 */
	public static final String createHashedHostname(String hostname)
	{
		MessageDigest sha1;
		try {
			sha1 = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("VM doesn't support SHA1", e);
		}

		byte[] salt = new byte[sha1.getDigestLength()];

		new SecureRandom().nextBytes(salt);

		byte[] hash = hmacSha1Hash(salt, hostname);

		String base64_salt = new String(Base64.encode(salt));
		String base64_hash = new String(Base64.encode(hash));

		return new String("|1|" + base64_salt + "|" + base64_hash);
	}

	private static final byte[] hmacSha1Hash(byte[] salt, String hostname)
	{
		Mac hmac;
		try {
			hmac = Mac.getInstance("HmacSHA1");
			if (salt.length != hmac.getMacLength())
				throw new IllegalArgumentException("Salt has wrong length (" + salt.length + ")");
			hmac.init(new SecretKeySpec(salt, "HmacSHA1"));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Unable to HMAC-SHA1", e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Unable to create SecretKey", e);
		}

		try {
			hmac.update(hostname.getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			hmac.update(hostname.getBytes());
		}

		return hmac.doFinal();
	}

	private final boolean checkHashed(String entry, String hostname)
	{
		if (!entry.startsWith("|1|"))
			return false;

		int delim_idx = entry.indexOf('|', 3);

		if (delim_idx == -1)
			return false;

		String salt_base64 = entry.substring(3, delim_idx);
		String hash_base64 = entry.substring(delim_idx + 1);

		byte[] salt = null;
		byte[] hash = null;

		try
		{
			salt = Base64.decode(salt_base64.toCharArray());
			hash = Base64.decode(hash_base64.toCharArray());
		}
		catch (IOException e)
		{
			return false;
		}

		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			if (salt.length != sha1.getDigestLength())
				return false;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("VM does not support SHA1", e);
		}

		byte[] dig = hmacSha1Hash(salt, hostname);

		for (int i = 0; i < dig.length; i++)
			if (dig[i] != hash[i])
				return false;

		return true;
	}

	private int checkKey(String remoteHostname, PublicKey remoteKey)
	{
		int result = HOSTKEY_IS_NEW;

		synchronized (publicKeys)
		{
			Iterator<KnownHostsEntry> i = publicKeys.iterator();

			while (i.hasNext())
			{
				KnownHostsEntry ke = i.next();

				if (!hostnameMatches(ke.patterns, remoteHostname))
					continue;

				boolean res = matchKeys(ke.key, remoteKey);

				if (res)
					return HOSTKEY_IS_OK;

				result = HOSTKEY_HAS_CHANGED;
			}
		}
		return result;
	}

	private List<PublicKey> getAllKeys(String hostname)
	{
		List<PublicKey> keys = new ArrayList<>();

		synchronized (publicKeys)
		{
			Iterator<KnownHostsEntry> i = publicKeys.iterator();

			while (i.hasNext())
			{
				KnownHostsEntry ke = i.next();

				if (!hostnameMatches(ke.patterns, hostname))
					continue;

				keys.add(ke.key);
			}
		}

		return keys;
	}

	/**
	 * Try to find the preferred order of hostkey algorithms for the given hostname.
	 * Based on the type of hostkey that is present in the internal database
	 * (i.e., either <code>ssh-rsa</code> or <code>ssh-dss</code>)
	 * an ordered list of hostkey algorithms is returned which can be passed
	 * to <code>Connection.setServerHostKeyAlgorithms</code>.
	 *
	 * @param hostname hostname to find preferred algorithm for
	 * @return <code>null</code> if no key for the given hostname is present or
	 * there are keys of multiple types present for the given hostname. Otherwise,
	 * an array with hostkey algorithms is returned (i.e., an array of length 2).
	 */
	public String[] getPreferredServerHostkeyAlgorithmOrder(String hostname)
	{
		String[] algos = recommendHostkeyAlgorithms(hostname);

		if (algos != null)
			return algos;

		InetAddress[] ipAddresses;

		try
		{
			ipAddresses = InetAddress.getAllByName(hostname);
		} catch (UnknownHostException e) {
			return null;
		}

		for (InetAddress ipAddress : ipAddresses) {
			algos = recommendHostkeyAlgorithms(ipAddress.getHostAddress());

			if (algos != null)
				return algos;
		}

		return null;
	}

	private final boolean hostnameMatches(String[] hostpatterns, String hostname)
	{
		boolean isMatch = false;
		boolean negate = false;

		if (hostname == null)
			return false;

		hostname = hostname.toLowerCase(Locale.US);

		for (int k = 0; k < hostpatterns.length; k++)
		{
			if (hostpatterns[k] == null)
				continue;

			String pattern = null;

			/* In contrast to OpenSSH we also allow negated hash entries (as well as hashed
			 * entries in lines with multiple entries).
			 */

			if ((hostpatterns[k].length() > 0) && (hostpatterns[k].charAt(0) == '!'))
			{
				pattern = hostpatterns[k].substring(1);
				negate = true;
			}
			else
			{
				pattern = hostpatterns[k];
				negate = false;
			}

			/* Optimize, no need to check this entry */

			if ((isMatch) && (!negate))
				continue;

			/* Now compare */

			if (pattern.charAt(0) == '|')
			{
				if (checkHashed(pattern, hostname))
				{
					if (negate)
						return false;
					isMatch = true;
				}
			}
			else
			{
				pattern = pattern.toLowerCase(Locale.US);

				if ((pattern.indexOf('?') != -1) || (pattern.indexOf('*') != -1))
				{
					if (pseudoRegex(pattern.toCharArray(), 0, hostname.toCharArray(), 0))
					{
						if (negate)
							return false;
						isMatch = true;
					}
				}
				else if (pattern.compareTo(hostname) == 0)
				{
					if (negate)
						return false;
					isMatch = true;
				}
			}
		}

		return isMatch;
	}

	private void initialize(char[] knownHostsData) throws IOException
	{
		BufferedReader br = new BufferedReader(new CharArrayReader(knownHostsData));

		while (true)
		{
			String line = br.readLine();

			if (line == null)
				break;

			line = line.trim();

			if (line.startsWith("#"))
				continue;

			String[] arr = line.split(" ");

			if (arr.length >= 3)
			{
				String[] hostnames = arr[0].split(",");

				byte[] msg = Base64.decode(arr[2].toCharArray());

				addHostkey(hostnames, arr[1], msg);
			}
		}
	}

	private void initialize(File knownHosts) throws IOException
	{
		char[] buff = new char[512];

		CharArrayWriter cw = new CharArrayWriter();

		knownHosts.createNewFile();

		FileReader fr = new FileReader(knownHosts);

		while (true)
		{
			int len = fr.read(buff);
			if (len < 0)
				break;
			cw.write(buff, 0, len);
		}

		fr.close();

		initialize(cw.toCharArray());
	}

	private final boolean matchKeys(PublicKey key1, PublicKey key2)
	{
		return key1.equals(key2);
	}

	private final boolean pseudoRegex(char[] pattern, int i, char[] match, int j)
	{
		/* This matching logic is equivalent to the one present in OpenSSH 4.1 */

		while (true)
		{
			/* Are we at the end of the pattern? */

			if (pattern.length == i)
				return (match.length == j);

			if (pattern[i] == '*')
			{
				i++;

				if (pattern.length == i)
					return true;

				if ((pattern[i] != '*') && (pattern[i] != '?'))
				{
					while (true)
					{
						if ((pattern[i] == match[j]) && pseudoRegex(pattern, i + 1, match, j + 1))
							return true;
						j++;
						if (match.length == j)
							return false;
					}
				}

				while (true)
				{
					if (pseudoRegex(pattern, i, match, j))
						return true;
					j++;
					if (match.length == j)
						return false;
				}
			}

			if (match.length == j)
				return false;

			if ((pattern[i] != '?') && (pattern[i] != match[j]))
				return false;

			i++;
			j++;
		}
	}

	private final String[] ALGOS_FOR_RSA = new String[] {
		RSASHA512Verify.ID_RSA_SHA_2_512,
		RSASHA256Verify.ID_RSA_SHA_2_256,
		RSASHA1Verify.ID_SSH_RSA,
	};

	private final String ALGO_FOR_DSS = DSASHA1Verify.ID_SSH_DSS;

	private final String ALGO_FOR_EDDSA = Ed25519Verify.ED25519_ID;

	private String[] recommendHostkeyAlgorithms(String hostname) {
		List<String> preferredAlgos = new ArrayList<>();

		List<PublicKey> keys = getAllKeys(hostname);

		for (PublicKey key : keys) {
			if (key instanceof RSAPublicKey) {
				preferredAlgos.addAll(Arrays.asList(ALGOS_FOR_RSA));
			} else if (key instanceof DSAPublicKey) {
				preferredAlgos.add(ALGO_FOR_DSS);
			} else if (key instanceof Ed25519PublicKey) {
				preferredAlgos.add(ALGO_FOR_EDDSA);
			} else if (key instanceof ECPublicKey) {
				preferredAlgos.add(ECDSASHA2Verify.getSshKeyType((ECPublicKey) key));
			}
		}

		/* If we did not find anything that we know of, return null */
		if (preferredAlgos.isEmpty())
			return null;

		/* Now put the preferred algo to the start of the array.
		 * You may ask yourself why we do it that way - basically, we could just
		 * return only the preferred algorithm: since we have a saved key of that
		 * type (sent earlier from the remote host), then that should work out.
		 * However, imagine that the server is (for whatever reasons) not offering
		 * that type of hostkey anymore (e.g., "ssh-rsa" was disabled and
		 * now "ssh-dss" is being used). If we then do not let the server send us
		 * a fresh key of the new type, then we shoot ourself into the foot:
		 * the connection cannot be established and hence the user cannot decide
		 * if he/she wants to accept the new key.
		 */

		List<String> preferredAndOthers = new ArrayList<>();
		List<String> notPreferred = new ArrayList<>();
		for (String algo : KexManager.getDefaultServerHostkeyAlgorithmList()) {
			if (preferredAlgos.contains(algo)) {
				preferredAndOthers.add(algo);
			} else {
				notPreferred.add(algo);
			}
		}
		preferredAndOthers.addAll(notPreferred);
		return preferredAndOthers.toArray(new String[0]);
	}

	/**
	 * Checks the internal hostkey database for the given hostkey.
	 * If no matching key can be found, then the hostname is resolved to an IP address
	 * and the search is repeated using that IP address.
	 *
	 * @param hostname the server's hostname, will be matched with all hostname patterns
	 * @param serverHostKeyAlgorithm type of hostkey, either <code>ssh-rsa</code> or <code>ssh-dss</code>
	 * @param serverHostKey the key blob
	 * @return <ul>
	 *         <li><code>HOSTKEY_IS_OK</code>: the given hostkey matches an entry for the given hostname</li>
	 *         <li><code>HOSTKEY_IS_NEW</code>: no entries found for this hostname and this type of hostkey</li>
	 *         <li><code>HOSTKEY_HAS_CHANGED</code>: hostname is known, but with another key of the same type
	 *         (man-in-the-middle attack?)</li>
	 *         </ul>
	 * @throws IOException if the supplied key blob cannot be parsed or does not match the given hostkey type.
	 */
	public int verifyHostkey(String hostname, String serverHostKeyAlgorithm, byte[] serverHostKey) throws IOException
	{
		PublicKey remoteKey = null;

		if (RSASHA1Verify.ID_SSH_RSA.equals(serverHostKeyAlgorithm) ||
			RSASHA256Verify.ID_RSA_SHA_2_256.equals(serverHostKeyAlgorithm) ||
			RSASHA512Verify.ID_RSA_SHA_2_512.equals(serverHostKeyAlgorithm))
		{
			remoteKey = RSASHA1Verify.get().decodePublicKey(serverHostKey);
		}
		else if (DSASHA1Verify.ID_SSH_DSS.equals(serverHostKeyAlgorithm))
		{
			remoteKey = DSASHA1Verify.get().decodePublicKey(serverHostKey);
		}
		else if (ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getKeyFormat().equals(serverHostKeyAlgorithm))
		{
			remoteKey = ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().decodePublicKey(serverHostKey);
		}
		else if (ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().getKeyFormat().equals(serverHostKeyAlgorithm))
		{
			remoteKey = ECDSASHA2Verify.ECDSASHA2NISTP384Verify.get().decodePublicKey(serverHostKey);
		}
		else if (ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().getKeyFormat().equals(serverHostKeyAlgorithm))
		{
			remoteKey = ECDSASHA2Verify.ECDSASHA2NISTP521Verify.get().decodePublicKey(serverHostKey);
		}
		else if (Ed25519Verify.ED25519_ID.equals(serverHostKeyAlgorithm))
		{
			remoteKey = Ed25519Verify.get().decodePublicKey(serverHostKey);
		}
		else
			throw new IllegalArgumentException("Unknown hostkey type " + serverHostKeyAlgorithm);

		int result = checkKey(hostname, remoteKey);

		if (result == HOSTKEY_IS_OK)
			return result;

		InetAddress[] ipAddresses = null;

		try
		{
			ipAddresses = InetAddress.getAllByName(hostname);
		}
		catch (UnknownHostException e)
		{
			return result;
		}

		for (InetAddress ipAddress : ipAddresses) {
			int newresult = checkKey(ipAddress.getHostAddress(), remoteKey);

			if (newresult == HOSTKEY_IS_OK)
				return newresult;

			if (newresult == HOSTKEY_HAS_CHANGED)
				result = HOSTKEY_HAS_CHANGED;
		}

		return result;
	}

	/**
	 * Adds a single public key entry to the a known_hosts file.
	 * This method is designed to be used in a {@link ServerHostKeyVerifier}.
	 *
	 * @param knownHosts the file where the publickey entry will be appended.
	 * @param hostnames a list of hostname patterns - at least one most be specified. Check out the
	 *        OpenSSH sshd man page for a description of the pattern matching algorithm.
	 * @param serverHostKeyAlgorithm as passed to the {@link ServerHostKeyVerifier}.
	 * @param serverHostKey as passed to the {@link ServerHostKeyVerifier}.
	 * @throws IOException on error
	 */
	public final static void addHostkeyToFile(File knownHosts, String[] hostnames, String serverHostKeyAlgorithm,
			byte[] serverHostKey) throws IOException
	{
		if ((hostnames == null) || (hostnames.length == 0))
			throw new IllegalArgumentException("Need at least one hostname specification");

		if ((serverHostKeyAlgorithm == null) || (serverHostKey == null))
			throw new IllegalArgumentException();

		CharArrayWriter writer = new CharArrayWriter();

		for (int i = 0; i < hostnames.length; i++)
		{
			if (i != 0)
				writer.write(',');
			writer.write(hostnames[i]);
		}

		writer.write(' ');
		writer.write(serverHostKeyAlgorithm);
		writer.write(' ');
		writer.write(Base64.encode(serverHostKey));
		writer.write("\n");

		char[] entry = writer.toCharArray();

		RandomAccessFile raf = new RandomAccessFile(knownHosts, "rw");

		long len = raf.length();

		if (len > 0)
		{
			raf.seek(len - 1);
			int last = raf.read();
			if (last != '\n')
				raf.write('\n');
		}

		try {
			raf.write(new String(entry).getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			raf.write(new String(entry).getBytes());
		}
		raf.close();
	}

	/**
	 * Convert a ssh2 key-blob into a human readable hex fingerprint.
	 * Generated fingerprints are identical to those generated by OpenSSH.
	 * <p>
	 * Example fingerprint: d0:cb:76:19:99:5a:03:fc:73:10:70:93:f2:44:63:47.

	 * @param keytype either "ssh-rsa" or "ssh-dss"
	 * @param publickey key blob
	 * @return Hex fingerprint
	 * @deprecated Use {@link KeyFingerprint#createMD5Fingerprint(byte[])} instead
	 */
	@Deprecated
	public final static String createHexFingerprint(String keytype, byte[] publickey)
	{
		return KeyFingerprint.createMD5Fingerprint(publickey);
	}

	/**
	 * Convert a ssh2 key-blob into a human readable bubblebabble fingerprint.
	 * The used bubblebabble algorithm (taken from OpenSSH) generates fingerprints
	 * that are easier to remember for humans.
	 * <p>
	 * Example fingerprint: xofoc-bubuz-cazin-zufyl-pivuk-biduk-tacib-pybur-gonar-hotat-lyxux.
	 *
	 * @param keytype either "ssh-rsa" or "ssh-dss"
	 * @param publickey key data
	 * @return Bubblebabble fingerprint
	 * @deprecated Use {@link KeyFingerprint#createBubblebabbleFingerprint(byte[])} instead
	 */
	@Deprecated
	public final static String createBubblebabbleFingerprint(String keytype, byte[] publickey)
	{
		return KeyFingerprint.createBubblebabbleFingerprint(publickey);
	}

	@Override
	public List<String> getKnownKeyAlgorithmsForHost(String hostname, int port)
	{
		List<PublicKey> keys = getAllKeys(hostname);
		List<String> algorithms = new ArrayList<>();

		for (PublicKey key : keys) {
			if (key instanceof RSAPublicKey) {
				algorithms.addAll(Arrays.asList(ALGOS_FOR_RSA));
			} else {
				String algo = publicKeyToAlgorithm(key);
				if (algo != null && !algorithms.contains(algo)) {
					algorithms.add(algo);
				}
			}
		}

		return algorithms;
	}

	@Override
	public void addServerHostKey(String hostname, int port, String keyAlgorithm, byte[] serverHostKey)
	{
		try {
			addVerifiedHostkey(hostname, keyAlgorithm, serverHostKey);
		} catch (IOException e) {
			// Log but don't throw - this is called from async context
			// Cannot use logger here since it's not available
		}
	}

	@Override
	public void removeServerHostKey(String hostname, int port, String serverHostKeyAlgorithm, byte[] serverHostKey)
	{
		synchronized (publicKeys) {
			publicKeys.removeIf(entry -> {
				if (!hostnameMatches(entry.patterns, hostname))
					return false;

				if (serverHostKeyAlgorithm == null)
					return false;

				String algo = publicKeyToAlgorithm(entry.key);
				return serverHostKeyAlgorithm.equals(algo);
			});
		}
	}

	@Override
	public boolean verifyServerHostKey(String hostname, int port,
										String serverHostKeyAlgorithm,
										byte[] serverHostKey) throws Exception
	{
		int result = verifyHostkey(hostname, serverHostKeyAlgorithm, serverHostKey);

		if (result == HOSTKEY_IS_OK) {
			return true;
		} else if (result == HOSTKEY_IS_NEW) {
			addHostkey(new String[]{hostname}, serverHostKeyAlgorithm, serverHostKey);
			return true;
		}

		return false;
	}

	public boolean addVerifiedHostkey(String hostname, String serverHostKeyAlgorithm,
										byte[] serverHostKey) throws IOException
	{
		int result = verifyHostkey(hostname, serverHostKeyAlgorithm, serverHostKey);
		if (result == HOSTKEY_IS_OK) {
			return false;
		}

		addHostkey(new String[]{hostname}, serverHostKeyAlgorithm, serverHostKey);
		return true;
	}

	private String publicKeyToAlgorithm(PublicKey key)
	{
		if (key instanceof RSAPublicKey) {
			return RSASHA1Verify.ID_SSH_RSA;
		} else if (key instanceof DSAPublicKey) {
			return DSASHA1Verify.ID_SSH_DSS;
		} else if (key instanceof ECPublicKey) {
			ECPublicKey ecKey = (ECPublicKey) key;
			int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
			if (fieldSize == 256) {
				return "ecdsa-sha2-nistp256";
			} else if (fieldSize == 384) {
				return "ecdsa-sha2-nistp384";
			} else if (fieldSize == 521) {
				return "ecdsa-sha2-nistp521";
			}
		} else if (key instanceof Ed25519PublicKey) {
			return Ed25519Verify.ED25519_ID;
		}
		return null;
	}
}
