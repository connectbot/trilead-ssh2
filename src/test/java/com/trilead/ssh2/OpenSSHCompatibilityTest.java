package com.trilead.ssh2;

import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.trilead.ssh2.crypto.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Integration tests against OpenSSH.
 *
 * @author Kenny Root
 */
public class OpenSSHCompatibilityTest {
	private static final Logger logger = LoggerFactory.getLogger(OpenSSHCompatibilityTest.class.getSimpleName());
	private static final Slf4jLogConsumer logConsumer = new Slf4jLogConsumer(logger).withPrefix("DOCKER");

	@RegisterExtension
	public SshLogger sshLogger = new SshLogger(logger);

	private static final String OPTIONS_ENV = "OPTIONS";
	private static final String USERNAME = "testuser";
	private static final String PASSWORD = "testtest123";

	private static final ImageFromDockerfile baseImage = new ImageFromDockerfile(
		"openssh-server", false)
				.withFileFromClasspath(".", "openssh-server");

	static {
		for (String key : PubkeyConstants.KEY_NAMES) {
			baseImage.withFileFromClasspath(key, "com/trilead/ssh2/crypto/" + key);
		}
	}

	private ExtendedServerHostKeyVerifier verifier = new TestExtendedHostKeyVerifier();

	@NotNull
	@Contract("_ -> new")
	private Connection withServer(@NotNull GenericContainer<?> container) {
		return new Connection(container.getHost(), container.getMappedPort(22));
	}

	private static GenericContainer<?> getBaseContainer() {
		return new GenericContainer<>(baseImage)
				.withExposedPorts(22)
				.withLogConsumer(logConsumer)
				.waitingFor(new LogMessageWaitStrategy()
						.withRegEx(".*Server listening on .*\\s"));
	}

	private ConnectionInfo assertCanPasswordAuthenticate(GenericContainer<?> server) throws IOException {
		try (Connection c = withServer(server)) {
			c.connect(verifier);
			assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
			try (Session s = c.openSession()) {
				s.ping();
			}
			return c.getConnectionInfo();
		}
	}

	private ConnectionInfo connectToServerWithOptions(@NotNull String options) throws IOException {
		try (GenericContainer<?> server = getBaseContainer().withEnv(OPTIONS_ENV, options)) {
			server.start();
			return assertCanPasswordAuthenticate(server);
		}
	}

	private void assertCanConnectToServerThatHasKeyType(@NotNull String keyPath, String keyType) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-h " + keyPath);
		assertThat(info.serverHostKeyAlgorithm, is(keyType));
	}

	private void canConnectWithPubkey(String keyFilename) throws Exception {
		char[] keyChars = IOUtils.toCharArray(getClass().getResourceAsStream("crypto/" + keyFilename), "UTF-8");

		try (GenericContainer<?> server = getBaseContainer()) {
			server.start();
			try (Connection connection = withServer(server)) {
				connection.connect(verifier);
				assertThat(connection.authenticateWithPublicKey(USERNAME, keyChars, ""), is(true));
				try (Session session = connection.openSession()) {
					session.ping();
				}
			}
		}
	}

	@Test
	public void publicKeyProbeThenSign() throws Exception {
		char[] keyChars = IOUtils.toCharArray(getClass().getResourceAsStream("crypto/ecdsa-nistp256-openssh2-private-key.txt"), "UTF-8");
		java.security.KeyPair key = com.trilead.ssh2.crypto.PEMDecoder.decode(keyChars, "");
		try (GenericContainer<?> server = getBaseContainer().withEnv(OPTIONS_ENV, "-o MaxAuthTries=1")) {
			server.start();
			try (Connection connection = withServer(server)) {
				connection.connect(verifier);
				assertThat(connection.probePublicKey(USERNAME, key.getPublic()), is(true));
				assertThat(connection.isAuthenticationComplete(), is(false));
				assertThat(connection.authenticateWithPublicKey(USERNAME, key), is(true));
			}
		}
	}

	@Test
	public void rejectedOffersExhaustProbeBudgetThenAuthLimit() throws Exception {
		java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
		generator.initialize(256);
		try (GenericContainer<?> server = getBaseContainer().withEnv(OPTIONS_ENV, "-o MaxAuthTries=2")) {
			server.start();
			try (Connection connection = withServer(server)) {
				connection.connect(verifier);
				// Current OpenSSH gives six probes a separate budget. The next
				// rejection uses one auth attempt; the following one disconnects.
				for (int i = 0; i < 7; i++) {
					assertThat(connection.probePublicKey(USERNAME, generator.generateKeyPair().getPublic()), is(false));
				}
				org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
						() -> connection.probePublicKey(USERNAME, generator.generateKeyPair().getPublic()));
			}
		}
	}

	@Test
	public void rejectedOffersThenAcceptedKeyWithinLimit() throws Exception {
		char[] chars = IOUtils.toCharArray(getClass().getResourceAsStream("crypto/ecdsa-nistp256-openssh2-private-key.txt"), "UTF-8");
		java.security.KeyPair key = com.trilead.ssh2.crypto.PEMDecoder.decode(chars, "");
		java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
		generator.initialize(256);
		try (GenericContainer<?> server = getBaseContainer().withEnv(OPTIONS_ENV, "-o MaxAuthTries=1")) {
			server.start();
			try (Connection connection = withServer(server)) {
				connection.connect(verifier);
				for (int i = 0; i < 6; i++) {
					assertThat(connection.probePublicKey(USERNAME, generator.generateKeyPair().getPublic()), is(false));
				}
				assertThat(connection.probePublicKey(USERNAME, key.getPublic()), is(true));
				assertThat(connection.authenticateWithPublicKey(USERNAME, key), is(true));
			}
		}
	}

	@Test
	public void testSocketAddress() throws IOException {
		try (GenericContainer<?> server = getBaseContainer()) {
			server.start();
			try (Connection c = withServer(server)) {
				c.connect(verifier);

				InetSocketAddress local = c.getLocalSocketAddress();
				InetSocketAddress remote = c.getRemoteSocketAddress();

				assertThat(local, notNullValue());
				assertThat(remote, notNullValue());
				assertThat(remote.getHostString(), is(server.getHost()));
				assertThat(remote.getPort(), is(server.getMappedPort(22)));

				ConnectionInfo info = c.getConnectionInfo();
				assertThat(info.localSocketAddress.toString(), is(local.toString()));
				assertThat(info.remoteSocketAddress.toString(), is(remote.toString()));
			}
		}
	}

	@Test
	public void canConnectWithEd25519() throws Exception {
		canConnectWithPubkey("ed25519-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa256() throws Exception {
		canConnectWithPubkey("ecdsa-nistp256-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa384() throws Exception {
		canConnectWithPubkey("ecdsa-nistp384-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithEcdsa521() throws Exception {
		canConnectWithPubkey("ecdsa-nistp521-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithRsa() throws Exception {
		canConnectWithPubkey("rsa-openssh2-private-key.txt");
	}

	@Test
	public void canConnectWithPassword() throws Exception {
		try (GenericContainer<?> server = getBaseContainer()) {
			server.start();
			assertCanPasswordAuthenticate(server);
		}
	}

	@Test
	public void wrongPasswordFails() throws Exception {
		try (GenericContainer<?> server = getBaseContainer()) {
			server.start();
			try (Connection c = withServer(server)) {
				c.connect(verifier);
				assertThat(c.authenticateWithPassword(USERNAME, "wrongpassword"), is(false));
			}
		}
	}

	@Test
	public void connectToRsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_rsa_key", "rsa-sha2-512");
	}

	@Test
	public void connectToEcdsaHost() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_ecdsa_key", "ecdsa-sha2-nistp256");
	}

	@Test
	public void connectToEd25519Host() throws Exception {
		assertCanConnectToServerThatHasKeyType("/etc/ssh/ssh_host_ed25519_key", "ssh-ed25519");
	}

	private void assertCanConnectToServerWithKex(@NotNull String kexType) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oKexAlgorithms=" + kexType);
		assertThat(info.keyExchangeAlgorithm, is(kexType));
	}

	@Test
	public void canConnectWithKexCurve25519LibsshOrg() throws Exception {
		assertCanConnectToServerWithKex("curve25519-sha256@libssh.org");
	}

	@Test
	public void canConnectWithKexCurve25519() throws Exception {
		assertCanConnectToServerWithKex("curve25519-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup1() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group1-sha1");
	}

	@Test
	public void canConnectWithKexDHGroup14() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha1");
	}

	@Test
	public void canConnectWithKexDHGroupExchangeSha1() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group-exchange-sha1");
	}

	@Test
	public void canConnectWithKexDHGroupExchangeSha256() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group-exchange-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup14Sha256() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group14-sha256");
	}

	@Test
	public void canConnectWithKexDHGroup16Sha512() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group16-sha512");
	}

	@Test
	public void canConnectWithKexDHGroup18Sha512() throws Exception {
		assertCanConnectToServerWithKex("diffie-hellman-group18-sha512");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp256() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp256");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp384() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp384");
	}

	@Test
	public void canConnectWithKexEcdhSha2Nistp521() throws Exception {
		assertCanConnectToServerWithKex("ecdh-sha2-nistp521");
	}

	@Test
	public void canConnectWithKexMlKem768X25519() throws Exception {
		Assumptions.assumeTrue(MlKemAvailability.isAvailable(), "ML-KEM not available on this JDK");
		assertCanConnectToServerWithKex("mlkem768x25519-sha256");
	}

	private void assertCanConnectToServerWithCipher(@NotNull String ciphers) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oCiphers=" + ciphers);
		assertThat(info.clientToServerCryptoAlgorithm, is(ciphers));
		assertThat(info.serverToClientCryptoAlgorithm, is(ciphers));
	}

	@Test
	public void canConnectWithCipherAes128Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes128-ctr");
	}

	@Test
	public void canConnectWithCipherAes256Ctr() throws Exception {
		assertCanConnectToServerWithCipher("aes256-ctr");
	}

	@Test
	public void canConnectWithCipherAes128Cbc() throws Exception {
		assertCanConnectToServerWithCipher("aes128-cbc");
	}

	@Test
	public void canConnectWithCipherAes256Cbc() throws Exception {
		assertCanConnectToServerWithCipher("aes256-cbc");
	}

	@Test
	public void canConnectWithCipher3desCbc() throws Exception {
		assertCanConnectToServerWithCipher("3des-cbc");
	}

	@Test
	public void canConnectWithCipherAes128Gcm() throws Exception {
		assertCanConnectToServerWithCipher("aes128-gcm@openssh.com");
	}

	@Test
	public void canConnectWithCipherAes256Gcm() throws Exception {
		assertCanConnectToServerWithCipher("aes256-gcm@openssh.com");
	}

	@Test
	public void canConnectWithCipherChaCha20Poly1305() throws Exception {
		assertCanConnectToServerWithCipher("chacha20-poly1305@openssh.com");
	}

	private void assertCanConnectToServerWithMac(@NotNull String macs) throws IOException {
		ConnectionInfo info = connectToServerWithOptions("-oCiphers=aes128-ctr -oMACs=" + macs);
		assertThat(info.clientToServerMACAlgorithm, is(macs));
		assertThat(info.serverToClientMACAlgorithm, is(macs));
	}

	@Test
	public void canConnectWithMacHmacSha1() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha1");
	}

	@Test
	public void canConnectWithMacHmacSha2_256() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-256");
	}

	@Test
	public void canConnectWithMacHmacSha2_512() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-512");
	}

	@Test
	public void canConnectWithMacHmacSha1Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha1-etm@openssh.com");
	}

	@Test
	public void canConnectWithMacHmacSha2_256Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-256-etm@openssh.com");
	}

	@Test
	public void canConnectWithMacHmacSha2_512Etm() throws Exception {
		assertCanConnectToServerWithMac("hmac-sha2-512-etm@openssh.com");
	}

	@Test
	public void canConnectWithCompression() throws Exception {
		try (GenericContainer<?> server = getBaseContainer()
				.withEnv(OPTIONS_ENV, "-oCompression=yes")) {
			server.start();
			try (Connection c = withServer(server)) {
				c.setCompression(true);
				c.connect(verifier);
				assertThat(c.authenticateWithPassword(USERNAME, PASSWORD), is(true));
				try (Session s = c.openSession()) {
					s.ping();
				}

				ConnectionInfo info = c.getConnectionInfo();
				assertThat(info.clientToServerCompressionAlgorithm, is("zlib@openssh.com"));
				assertThat(info.serverToClientCompressionAlgorithm, is("zlib@openssh.com"));
			}
		}
	}

	private void canConnectWithHostKeyAlgorithm(String keyPath, String hostKeyAlgorithm) throws Exception {
		ConnectionInfo info = connectToServerWithOptions("-h " + keyPath + " -oHostKeyAlgorithms=" + hostKeyAlgorithm);
		assertThat(info.serverHostKeyAlgorithm, is(hostKeyAlgorithm));
	}

	@Test
	public void canConnectToHostWithHostKeyRsaSha512() throws Exception {
		canConnectWithHostKeyAlgorithm("/etc/ssh/ssh_host_rsa_key", "rsa-sha2-512");
	}

	@Test
	public void canConnectToHostWithHostKeyRsaSha256() throws Exception {
		canConnectWithHostKeyAlgorithm("/etc/ssh/ssh_host_rsa_key", "rsa-sha2-256");
	}

	@Test
	public void canConnectToHostWithHostKeySshRsa() throws Exception {
		canConnectWithHostKeyAlgorithm("/etc/ssh/ssh_host_rsa_key", "ssh-rsa");
	}

	@Test
	public void canConnectAndRotateHostKey() throws Exception {
		try (GenericContainer<?> server = getBaseContainer()) {
			server.start();

			// Get the RSA host key from the server
			Container.ExecResult result = server.execInContainer("cat", "/etc/ssh/ssh_host_rsa_key.pub");
			String rsaPublicKey = result.getStdout().trim();
			// Format: ssh-rsa <blob> <comment>
			String[] parts = rsaPublicKey.split(" ");
			String keyType = parts[0];
			String keyBlob = parts[1];
			byte[] keyBytes = Base64.decode(keyBlob.toCharArray());

			// Setup KnownHosts with only the RSA key
			KnownHosts knownHosts = new KnownHosts();
			knownHosts.addHostkey(new String[] { server.getHost() }, keyType, keyBytes);

			// Verify we can connect with this setup
			try (Connection c = withServer(server)) {
				c.connect(knownHosts);
				c.authenticateWithPassword(USERNAME, PASSWORD);

				// Now wait for the hostkeys-00@openssh.com global request to be processed.
				// This happens asynchronously.
				// We can poll KnownHosts until we see the ed25519 key.

				long start = System.currentTimeMillis();
				boolean found = false;
				while (System.currentTimeMillis() - start < 10000) {
					// Check if we have ed25519 key for this host
					String[] algos = knownHosts.getPreferredServerHostkeyAlgorithmOrder(server.getHost());
					if (algos != null) {
						for (String algo : algos) {
							if ("ssh-ed25519".equals(algo)) {
								found = true;
								break;
							}
						}
					}
					if (found)
						break;
					Thread.sleep(100);
				}

				assertThat("Should have received and processed hostkeys-00@openssh.com update", found, is(true));
			}
		}
	}
}
