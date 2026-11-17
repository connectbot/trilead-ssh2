package com.trilead.ssh2.crypto.dh;

import com.trilead.ssh2.log.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 * Factory for creating X25519Provider instances.
 * Selects the first platform provider that passes the X25519 capability probe,
 * falling back to Tink when none pass.
 */
public class X25519ProviderFactory {
	private static final Logger log = Logger.getLogger(X25519ProviderFactory.class);

	// RFC 7748, section 6.1.
	private static final byte[] PROBE_PRIVATE = decodeHex(
			"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	private static final byte[] PROBE_PUBLIC = decodeHex(
			"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
	private static final byte[] PROBE_PEER = decodeHex(
			"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
	private static final byte[] PROBE_SECRET = decodeHex(
			"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

	private static final X25519Provider INSTANCE = selectProvider(Security.getProviders());

	static X25519Provider selectProvider(Provider[] providers) {
		try {
			Class.forName("java.security.spec.XECPrivateKeySpec");
			for (Provider provider : providers) {
				try {
					PlatformX25519Provider candidate = new PlatformX25519Provider(provider);
					if (candidate.generatePrivateKey().length == X25519Provider.KEY_SIZE
							&& Arrays.equals(candidate.publicFromPrivate(PROBE_PRIVATE), PROBE_PUBLIC)
							&& Arrays.equals(candidate.computeSharedSecret(PROBE_PRIVATE, PROBE_PEER), PROBE_SECRET)) {
						log.log(20, "Using platform-native X25519 implementation from " + provider.getName());
						return candidate;
					}
					log.log(20, "X25519 capability probe returned unexpected results from " + provider.getName());
				} catch (Exception | LinkageError e) {
					log.log(20, "X25519 capability probe failed for " + provider.getName() + ": " + e);
				}
			}
		} catch (ClassNotFoundException | LinkageError e) {
			log.log(20, "Platform X25519 key specifications are unavailable: " + e);
		}

		log.log(20, "No platform provider passed the X25519 capability probe; using Tink");
		return new TinkX25519Provider();
	}

	private static byte[] decodeHex(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
		}
		return bytes;
	}

	public static X25519Provider getProvider() {
		return INSTANCE;
	}

	public static boolean isPlatformNative() {
		return INSTANCE instanceof PlatformX25519Provider;
	}

	public static X25519Provider getTinkProvider() {
		return new TinkX25519Provider();
	}

	public static X25519Provider getPlatformProvider() {
		if (!(INSTANCE instanceof PlatformX25519Provider platform)) {
			throw new UnsupportedOperationException("Platform-native X25519 not available");
		}
		try {
			return new PlatformX25519Provider(platform.getJcaProvider());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Previously selected platform X25519 provider is unavailable", e);
		}
	}
}
