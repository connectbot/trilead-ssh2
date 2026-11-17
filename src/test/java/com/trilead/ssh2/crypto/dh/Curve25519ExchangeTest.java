package com.trilead.ssh2.crypto.dh;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Created by Kenny Root on 1/23/16.
 */
public class Curve25519ExchangeTest {
	private static final byte[] ALICE_PRIVATE = toByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	private static final byte[] ALICE_PUBLIC = toByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

	private static final byte[] BOB_PRIVATE = toByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
	private static final byte[] BOB_PUBLIC = toByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

	private static final byte[] KNOWN_SHARED_SECRET = toByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
	private static final BigInteger KNOWN_SHARED_SECRET_BI = new BigInteger(1, KNOWN_SHARED_SECRET);

	private static byte[] toByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int hexIndex = i * 2;
			int hexDigit = Integer.parseInt(s.substring(hexIndex, hexIndex + 2), 16);
			b[i] = (byte) hexDigit;
		}
		return b;
	}

	static Stream<X25519Provider> providers() {
		Stream.Builder<X25519Provider> builder = Stream.builder();
		builder.add(X25519ProviderFactory.getTinkProvider());
		if (X25519ProviderFactory.isPlatformNative()) {
			builder.add(X25519ProviderFactory.getPlatformProvider());
		}
		return builder.build();
	}

	@ParameterizedTest
	@MethodSource("providers")
	public void selfAgreement(X25519Provider provider) throws Exception {
		byte[] alicePrivKey = provider.generatePrivateKey();
		byte[] alicePubKey = provider.publicFromPrivate(alicePrivKey);

		byte[] bobPrivKey = provider.generatePrivateKey();
		byte[] bobPubKey = provider.publicFromPrivate(bobPrivKey);

		Curve25519Exchange alice = new Curve25519Exchange(provider, alicePrivKey);
		alice.setF(bobPubKey);

		Curve25519Exchange bob = new Curve25519Exchange(provider, bobPrivKey);
		bob.setF(alicePubKey);

		assertNotNull(alice.sharedSecret);
		assertEquals(alice.sharedSecret, bob.sharedSecret);
	}

	@ParameterizedTest
	@MethodSource("providers")
	public void deriveAlicePublicKey(X25519Provider provider) throws Exception {
		byte[] pubKey = provider.publicFromPrivate(ALICE_PRIVATE);
		assertArrayEquals(ALICE_PUBLIC, pubKey);
	}

	@ParameterizedTest
	@MethodSource("providers")
	public void deriveBobPublicKey(X25519Provider provider) throws Exception {
		byte[] pubKey = provider.publicFromPrivate(BOB_PRIVATE);
		assertArrayEquals(BOB_PUBLIC, pubKey);
	}

	@ParameterizedTest
	@MethodSource("providers")
	public void knownValues_Alice(X25519Provider provider) throws Exception {
		Curve25519Exchange ex = new Curve25519Exchange(provider, ALICE_PRIVATE);
		ex.setF(BOB_PUBLIC);
		assertEquals(KNOWN_SHARED_SECRET_BI, ex.sharedSecret);
	}

	@ParameterizedTest
	@MethodSource("providers")
	public void knownValues_Bob(X25519Provider provider) throws Exception {
		Curve25519Exchange ex = new Curve25519Exchange(provider, BOB_PRIVATE);
		ex.setF(ALICE_PUBLIC);
		assertEquals(KNOWN_SHARED_SECRET_BI, ex.sharedSecret);
	}

	@Test
	public void crossProviderAgreement() throws Exception {
		if (!X25519ProviderFactory.isPlatformNative()) {
			return;
		}

		X25519Provider tink = X25519ProviderFactory.getTinkProvider();
		X25519Provider platform = X25519ProviderFactory.getPlatformProvider();

		byte[] alicePrivKey = tink.generatePrivateKey();
		byte[] alicePubKey = tink.publicFromPrivate(alicePrivKey);

		byte[] bobPrivKey = platform.generatePrivateKey();
		byte[] bobPubKey = platform.publicFromPrivate(bobPrivKey);

		Curve25519Exchange alice = new Curve25519Exchange(tink, alicePrivKey);
		alice.setF(bobPubKey);

		Curve25519Exchange bob = new Curve25519Exchange(platform, bobPrivKey);
		bob.setF(alicePubKey);

		assertNotNull(alice.sharedSecret);
		assertEquals(alice.sharedSecret, bob.sharedSecret);
	}

	@Test
	public void skipsProviderThatRejectsScalarExtraction() throws Exception {
		Provider rejecting = new RejectingScalarProvider();
		Provider working = KeyPairGenerator.getInstance("X25519").getProvider();
		PlatformX25519Provider broken = new PlatformX25519Provider(rejecting);
		// The same generator and factory lookups that Trilead previously used succeed.
		assertInstanceOf(InvalidKeySpecException.class,
				assertThrows(IllegalStateException.class, broken::generatePrivateKey).getCause());

		PlatformX25519Provider selected = assertInstanceOf(PlatformX25519Provider.class,
				X25519ProviderFactory.selectProvider(new Provider[] {rejecting, working}));
		assertSame(working, selected.getJcaProvider());
		assertArrayEquals(KNOWN_SHARED_SECRET, selected.computeSharedSecret(ALICE_PRIVATE, BOB_PUBLIC));
	}

	@Test
	public void fallsBackToTinkWhenNoProviderPasses() throws Exception {
		X25519Provider selected = X25519ProviderFactory.selectProvider(new Provider[] {new RejectingScalarProvider()});
		assertInstanceOf(TinkX25519Provider.class, selected);
		assertArrayEquals(KNOWN_SHARED_SECRET, selected.computeSharedSecret(ALICE_PRIVATE, BOB_PUBLIC));
	}

	private static final class RejectingScalarProvider extends Provider {
		RejectingScalarProvider() {
			super("RejectingScalar", 1.0, "Rejects X25519 scalar extraction");
			put("KeyPairGenerator.X25519", DelegatingGenerator.class.getName());
			put("KeyFactory.X25519", RejectingKeyFactory.class.getName());
		}
	}

	public static final class DelegatingGenerator extends KeyPairGeneratorSpi {
		@Override
		public void initialize(int keysize, SecureRandom random) {
			throw new UnsupportedOperationException();
		}

		@Override
		public KeyPair generateKeyPair() {
			try {
				return KeyPairGenerator.getInstance("X25519").generateKeyPair();
			} catch (NoSuchAlgorithmException e) {
				throw new ProviderException(e);
			}
		}
	}

	public static final class RejectingKeyFactory extends KeyFactorySpi {
		@Override
		protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
			throw new InvalidKeySpecException("Injected scalar extraction failure");
		}

		@Override
		protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
			throw new InvalidKeySpecException();
		}

		@Override
		protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
			throw new InvalidKeySpecException();
		}

		@Override
		protected Key engineTranslateKey(Key key) {
			throw new UnsupportedOperationException();
		}
	}
}
