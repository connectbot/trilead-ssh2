package com.trilead.ssh2.crypto.dh;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;

import javax.crypto.KeyAgreement;

/**
 * X25519 provider implementation using platform-native APIs (Java 11+/Android
 * API 33+).
 */
public class PlatformX25519Provider implements X25519Provider {
	private static final String ALGORITHM = "X25519";

	private final KeyPairGenerator keyPairGenerator;
	private final KeyFactory keyFactory;
	private final Provider provider;

	public PlatformX25519Provider() {
		this(defaultKeyPairGenerator());
	}

	PlatformX25519Provider(Provider provider) throws NoSuchAlgorithmException {
		this(KeyPairGenerator.getInstance(ALGORITHM, provider));
	}

	private PlatformX25519Provider(KeyPairGenerator generator) {
		keyPairGenerator = generator;
		provider = generator.getProvider();
		try {
			keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("X25519 KeyFactory unavailable from " + provider.getName(), e);
		}
	}

	private static KeyPairGenerator defaultKeyPairGenerator() {
		try {
			return KeyPairGenerator.getInstance(ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("X25519 not available on this platform", e);
		}
	}

	Provider getJcaProvider() {
		return provider;
	}

	@Override
	public byte[] generatePrivateKey() {
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return extractPrivateKeyBytes(keyPair.getPrivate());
	}

	@Override
	public byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
		byte[] pubKeyBytes = new byte[KEY_SIZE];
		computePublicFromPrivate(privateKey, pubKeyBytes);
		return pubKeyBytes;
	}

	private static final byte[] BASE_POINT = new byte[KEY_SIZE];
	static {
		BASE_POINT[0] = 9;
	}

	private void computePublicFromPrivate(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
		try {
			PrivateKey privKey = createPrivateKey(privateKey);
			KeyAgreement ka = KeyAgreement.getInstance(ALGORITHM, provider);
			ka.init(privKey);

			PublicKey basePoint = createPublicKey(BASE_POINT);
			ka.doPhase(basePoint, true);
			byte[] result = ka.generateSecret();
			System.arraycopy(result, 0, publicKey, 0, KEY_SIZE);
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidKeyException("X25519 not available", e);
		}
	}

	@Override
	public byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) throws InvalidKeyException {
		try {
			PrivateKey privKey = createPrivateKey(privateKey);
			PublicKey pubKey = createPublicKey(publicKey);

			KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM, provider);
			keyAgreement.init(privKey);
			keyAgreement.doPhase(pubKey, true);

			return keyAgreement.generateSecret();
		} catch (NoSuchAlgorithmException e) {
			throw new InvalidKeyException("X25519 not available", e);
		}
	}

	private static final byte[] PKCS8_PREFIX = {
			0x30, 0x2e, // SEQUENCE (46 bytes)
			0x02, 0x01, 0x00, // INTEGER 0 (version)
			0x30, 0x05, // SEQUENCE (5 bytes)
			0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
			0x04, 0x22, // OCTET STRING (34 bytes)
			0x04, 0x20 // OCTET STRING (32 bytes) - key follows
	};

	private static final byte[] X509_PREFIX = {
			0x30, 0x2a, // SEQUENCE (42 bytes)
			0x30, 0x05, // SEQUENCE (5 bytes)
			0x06, 0x03, 0x2b, 0x65, 0x6e, // OID 1.3.101.110 (X25519)
			0x03, 0x21, 0x00 // BIT STRING (33 bytes, 0 unused bits)
	};

	private PrivateKey createPrivateKey(byte[] keyBytes) throws InvalidKeyException {
		try {
			byte[] pkcs8 = new byte[PKCS8_PREFIX.length + KEY_SIZE];
			System.arraycopy(PKCS8_PREFIX, 0, pkcs8, 0, PKCS8_PREFIX.length);
			System.arraycopy(keyBytes, 0, pkcs8, PKCS8_PREFIX.length, KEY_SIZE);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
			return keyFactory.generatePrivate(spec);
		} catch (InvalidKeySpecException e) {
			throw new InvalidKeyException("Invalid private key", e);
		}
	}

	private PublicKey createPublicKey(byte[] keyBytes) throws InvalidKeyException {
		try {
			byte[] x509 = new byte[X509_PREFIX.length + KEY_SIZE];
			System.arraycopy(X509_PREFIX, 0, x509, 0, X509_PREFIX.length);
			System.arraycopy(keyBytes, 0, x509, X509_PREFIX.length, KEY_SIZE);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(x509);
			return keyFactory.generatePublic(spec);
		} catch (InvalidKeySpecException e) {
			throw new InvalidKeyException("Invalid public key", e);
		}
	}

	private byte[] extractPrivateKeyBytes(PrivateKey privateKey) {
		try {
			XECPrivateKeySpec spec = keyFactory.getKeySpec(privateKey, XECPrivateKeySpec.class);
			byte[] scalar = spec.getScalar();
			if (scalar == null) {
				throw new IllegalStateException("Private key scalar not available");
			}
			if (scalar.length == KEY_SIZE) {
				return scalar;
			}
			byte[] padded = new byte[KEY_SIZE];
			System.arraycopy(scalar, 0, padded, KEY_SIZE - scalar.length, scalar.length);
			return padded;
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Failed to extract private key bytes", e);
		}
	}

}
