package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ML-KEM-768 hybrid key exchange implementation (mlkem768x25519-sha256).
 * Combines post-quantum ML-KEM-768 with classical X25519 key exchange.
 * Supports both Java 23+ native KEM API and Kyber Kotlin fallback for Android.
 * Implements draft-ietf-sshm-mlkem-hybrid-kex-03 specification.
 */
public class MlKemHybridExchange extends GenericDhExchange {

	public static final String NAME = "mlkem768x25519-sha256";
	private static final int MLKEM768_PUBLIC_KEY_SIZE = 1184;
	private static final int MLKEM768_CIPHERTEXT_SIZE = 1088;
	private static final int MLKEM768_SHARED_SECRET_SIZE = 32;
	private static final int X25519_KEY_SIZE = 32;

	private byte[] mlkemPublicKey;
	private byte[] mlkemPrivateKey;
	private byte[] x25519PublicKey;
	private byte[] x25519PrivateKey;

	private byte[] mlkemSharedSecret;
	private byte[] x25519SharedSecret;
	private byte[] serverX25519PublicKey;
	private byte[] serverReply;
	private byte[] hybridSharedSecretK;

	private final MlKemAdapter mlkemAdapter;

	public MlKemHybridExchange() throws IOException {
		super();
		this.mlkemAdapter = createMlKemAdapter();
	}

	public MlKemHybridExchange(MlKemAdapter adapter) {
		super();
		this.mlkemAdapter = adapter;
	}

	private static MlKemAdapter createMlKemAdapter() throws IOException {
		try {
			return new JavaKemAdapter();
		} catch (IOException e) {
			return new KyberKotlinAdapter();
		}
	}

	@Override
	public void init(String name) throws IOException {
		if (!NAME.equals(name)) {
			throw new IOException("Invalid algorithm: " + name);
		}

		try {
			MlKemAdapter.MlKemKeyPair mlkemKeyPair = mlkemAdapter.generateKeyPair();
			mlkemPublicKey = mlkemKeyPair.getPublicKey();
			mlkemPrivateKey = mlkemKeyPair.getPrivateKey();

			if (mlkemPublicKey.length != MLKEM768_PUBLIC_KEY_SIZE) {
				throw new IOException(
						"Unexpected ML-KEM-768 public key size: "
								+ mlkemPublicKey.length
								+ " (expected "
								+ MLKEM768_PUBLIC_KEY_SIZE
								+ ")");
			}

			x25519PrivateKey = X25519.generatePrivateKey();
			x25519PublicKey = X25519.publicFromPrivate(x25519PrivateKey);

			if (x25519PublicKey.length != X25519_KEY_SIZE) {
				throw new IOException(
						"Unexpected X25519 public key size: "
								+ x25519PublicKey.length
								+ " (expected "
								+ X25519_KEY_SIZE
								+ ")");
			}

		} catch (InvalidKeyException | RuntimeException e) {
			throw new IOException("Failed to generate key pair", e);
		}
	}

	@Override
	public byte[] getE() {
		byte[] init = new byte[mlkemPublicKey.length + x25519PublicKey.length];
		System.arraycopy(mlkemPublicKey, 0, init, 0, mlkemPublicKey.length);
		System.arraycopy(
				x25519PublicKey, 0, init, mlkemPublicKey.length, x25519PublicKey.length);
		return init;
	}

	@Override
	protected byte[] getServerE() {
		return serverReply != null ? serverReply.clone() : new byte[0];
	}

	@Override
	public void setF(byte[] f) throws IOException {
		if (f.length != MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE) {
			throw new IOException(
					"Invalid S_REPLY length: "
							+ f.length
							+ " (expected "
							+ (MLKEM768_CIPHERTEXT_SIZE + X25519_KEY_SIZE)
							+ ")");
		}

		serverReply = f.clone();

		try {
			byte[] mlkemCiphertext = new byte[MLKEM768_CIPHERTEXT_SIZE];
			System.arraycopy(f, 0, mlkemCiphertext, 0, MLKEM768_CIPHERTEXT_SIZE);

			serverX25519PublicKey = new byte[X25519_KEY_SIZE];
			System.arraycopy(f, MLKEM768_CIPHERTEXT_SIZE, serverX25519PublicKey, 0, X25519_KEY_SIZE);

			mlkemSharedSecret = mlkemAdapter.decapsulate(mlkemPrivateKey, mlkemCiphertext);

			x25519SharedSecret = X25519.computeSharedSecret(x25519PrivateKey, serverX25519PublicKey);
			validateX25519SharedSecret(x25519SharedSecret);

			byte[] combined = new byte[MLKEM768_SHARED_SECRET_SIZE + X25519_KEY_SIZE];
			System.arraycopy(mlkemSharedSecret, 0, combined, 0, MLKEM768_SHARED_SECRET_SIZE);
			System.arraycopy(x25519SharedSecret, 0, combined, MLKEM768_SHARED_SECRET_SIZE, X25519_KEY_SIZE);

			hybridSharedSecretK = computeHybridSharedSecret(combined);
			sharedSecret = new BigInteger(1, hybridSharedSecretK);

		} catch (InvalidKeyException e) {
			throw new IOException("X25519 key agreement failed", e);
		} catch (Exception e) {
			throw new IOException("ML-KEM decapsulation or key agreement failed", e);
		}
	}

	private void validateX25519SharedSecret(byte[] sharedSecret) throws IOException {
		int allBytes = 0;
		for (int i = 0; i < sharedSecret.length; i++) {
			allBytes |= sharedSecret[i];
		}
		if (allBytes == 0) {
			throw new IOException("Invalid X25519 shared secret; all zeroes");
		}
	}

	private byte[] computeHybridSharedSecret(byte[] combined) throws IOException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			return md.digest(combined);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-256 not available", e);
		}
	}

	@Override
	public String getHashAlgo() {
		return "SHA-256";
	}

	@Override
	public byte[] getK() {
		if (hybridSharedSecretK == null) {
			throw new IllegalStateException("Shared secret not yet known, need f first!");
		}
		return hybridSharedSecretK.clone();
	}
}
