package com.trilead.ssh2.crypto.dh;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * ML-KEM adapter using Java 23+ native javax.crypto.KEM API.
 * Uses reflection to maintain compatibility with Java 11+.
 */
public class JavaKemAdapter implements MlKemAdapter {

	private static final int MLKEM768_PUBLIC_KEY_SIZE = 1184;
	private static final int MLKEM768_CIPHERTEXT_SIZE = 1088;

	private final Object kemInstance;

	public JavaKemAdapter() throws IOException {
		try {
			// A provider can register key generation without exposing the KEM API.
			KeyPairGenerator.getInstance("ML-KEM-768");
			Class<?> kemClass = Class.forName("javax.crypto.KEM");
			Method getInstance = kemClass.getMethod("getInstance", String.class);
			kemInstance = getInstance.invoke(null, "ML-KEM");
		} catch (Exception | LinkageError e) {
			throw new IOException("Failed to initialize Java ML-KEM-768", e);
		}
	}

	@Override
	public MlKemKeyPair generateKeyPair() throws IOException {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
			KeyPair keyPair = kpg.generateKeyPair();

			byte[] x509PublicKey = keyPair.getPublic().getEncoded();
			byte[] pkcs8PrivateKey = keyPair.getPrivate().getEncoded();

			byte[] rawPublicKey = extractRawMlKemPublicKey(x509PublicKey);

			return new JavaKemKeyPair(rawPublicKey, pkcs8PrivateKey);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("ML-KEM-768 not available", e);
		}
	}

	@Override
	public MlKemEncapsulationResult encapsulate(byte[] publicKey) throws IOException {
		try {
			byte[] x509EncodedPublicKey = wrapRawMlKemPublicKey(publicKey);
			KeyFactory kf = KeyFactory.getInstance("ML-KEM");
			java.security.spec.X509EncodedKeySpec publicKeySpec =
					new java.security.spec.X509EncodedKeySpec(x509EncodedPublicKey);
			java.security.PublicKey mlkemPublicKey = kf.generatePublic(publicKeySpec);

			Class<?> kemClass = Class.forName("javax.crypto.KEM");
			Method newEncapsulator = kemClass.getMethod("newEncapsulator", java.security.PublicKey.class);
			Object encapsulator = newEncapsulator.invoke(kemInstance, mlkemPublicKey);

			Class<?> encapsulatorClass = Class.forName("javax.crypto.KEM$Encapsulator");
			Method encapsulateMethod = encapsulatorClass.getMethod("encapsulate");
			Object encapsulated = encapsulateMethod.invoke(encapsulator);

			Class<?> encapsulatedClass = Class.forName("javax.crypto.KEM$Encapsulated");
			Method encapsulationMethod = encapsulatedClass.getMethod("encapsulation");
			byte[] ciphertext = (byte[]) encapsulationMethod.invoke(encapsulated);

			Method keyMethod = encapsulatedClass.getMethod("key");
			javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey) keyMethod.invoke(encapsulated);
			byte[] sharedSecret = secretKey.getEncoded();

			return new JavaKemEncapsulationResult(ciphertext, sharedSecret);

		} catch (Exception e) {
			throw new IOException("ML-KEM encapsulation failed", e);
		}
	}

	@Override
	public byte[] decapsulate(byte[] privateKey, byte[] ciphertext) throws IOException {
		try {
			KeyFactory kf = KeyFactory.getInstance("ML-KEM");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey);
			PrivateKey mlkemPrivateKey = kf.generatePrivate(privateKeySpec);

			Class<?> kemClass = Class.forName("javax.crypto.KEM");
			Method newDecapsulator = kemClass.getMethod("newDecapsulator", PrivateKey.class);
			Object decapsulator = newDecapsulator.invoke(kemInstance, mlkemPrivateKey);

			Class<?> decapsulatorClass = Class.forName("javax.crypto.KEM$Decapsulator");
			Method decapsulateMethod = decapsulatorClass.getMethod("decapsulate", byte[].class);
			Object secretKey = decapsulateMethod.invoke(decapsulator, ciphertext);

			javax.crypto.SecretKey sk = (javax.crypto.SecretKey) secretKey;
			return sk.getEncoded();

		} catch (Exception e) {
			throw new IOException("ML-KEM decapsulation failed", e);
		}
	}

	private static byte[] extractRawMlKemPublicKey(byte[] x509Encoded) throws IOException {
		if (x509Encoded.length < 22) {
			throw new IOException("X.509 encoded ML-KEM public key too short");
		}

		if (x509Encoded[0] != 0x30) {
			throw new IOException("Invalid X.509 encoding: expected SEQUENCE tag");
		}

		if (x509Encoded[17] != 0x03) {
			throw new IOException("Invalid X.509 encoding: BIT STRING not found at expected position");
		}

		if (x509Encoded[21] != 0x00) {
			throw new IOException("Invalid X.509 encoding: unexpected unused bits in BIT STRING");
		}

		byte[] rawKey = new byte[MLKEM768_PUBLIC_KEY_SIZE];
		System.arraycopy(x509Encoded, 22, rawKey, 0, MLKEM768_PUBLIC_KEY_SIZE);
		return rawKey;
	}

	private static byte[] wrapRawMlKemPublicKey(byte[] rawKey) throws IOException {
		if (rawKey.length != MLKEM768_PUBLIC_KEY_SIZE) {
			throw new IOException("Invalid raw ML-KEM public key size: " + rawKey.length);
		}

		byte[] x509 = new byte[1206];
		x509[0] = 0x30;
		x509[1] = (byte) 0x82;
		x509[2] = 0x04;
		x509[3] = (byte) 0xb2;
		x509[4] = 0x30;
		x509[5] = 0x0b;
		x509[6] = 0x06;
		x509[7] = 0x09;
		x509[8] = 0x60;
		x509[9] = (byte) 0x86;
		x509[10] = 0x48;
		x509[11] = 0x01;
		x509[12] = 0x65;
		x509[13] = 0x03;
		x509[14] = 0x04;
		x509[15] = 0x04;
		x509[16] = 0x02;
		x509[17] = 0x03;
		x509[18] = (byte) 0x82;
		x509[19] = 0x04;
		x509[20] = (byte) 0xa1;
		x509[21] = 0x00;

		System.arraycopy(rawKey, 0, x509, 22, MLKEM768_PUBLIC_KEY_SIZE);

		return x509;
	}

	private static class JavaKemKeyPair implements MlKemKeyPair {
		private final byte[] publicKey;
		private final byte[] privateKey;

		JavaKemKeyPair(byte[] publicKey, byte[] privateKey) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}

		@Override
		public byte[] getPublicKey() {
			return publicKey;
		}

		@Override
		public byte[] getPrivateKey() {
			return privateKey;
		}
	}

	private static class JavaKemEncapsulationResult implements MlKemEncapsulationResult {
		private final byte[] ciphertext;
		private final byte[] sharedSecret;

		JavaKemEncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {
			this.ciphertext = ciphertext;
			this.sharedSecret = sharedSecret;
		}

		@Override
		public byte[] getCiphertext() {
			return ciphertext;
		}

		@Override
		public byte[] getSharedSecret() {
			return sharedSecret;
		}
	}
}
