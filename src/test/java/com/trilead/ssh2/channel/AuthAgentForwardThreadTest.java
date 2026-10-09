/*
 * Copyright 2026 Kenny Root
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.trilead.ssh2.channel;

import com.trilead.ssh2.AuthAgentCallback;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthAgentForwardThreadTest {

	private static final byte[] CHALLENGE = "agent signing challenge".getBytes(StandardCharsets.UTF_8);

	private byte[] sign(KeyPair pair, byte[] publicKey, int flags) throws Exception {
		AuthAgentCallback callback = mock(AuthAgentCallback.class);
		when(callback.getKeyPair(publicKey)).thenReturn(pair);
		AuthAgentForwardThread agent = new AuthAgentForwardThread(null, callback);
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		agent.os = output;

		TypesWriter request = new TypesWriter();
		request.writeString(publicKey, 0, publicKey.length);
		request.writeString(CHALLENGE, 0, CHALLENGE.length);
		request.writeUINT32(flags);

		Method signRequest = AuthAgentForwardThread.class.getDeclaredMethod("processSignRequest", TypesReader.class);
		signRequest.setAccessible(true);
		signRequest.invoke(agent, new TypesReader(request.getBytes()));
		return output.toByteArray();
	}

	@ParameterizedTest
	@CsvSource({
		"secp256r1, ecdsa-sha2-nistp256",
		"secp384r1, ecdsa-sha2-nistp384",
		"secp521r1, ecdsa-sha2-nistp521"
	})
	public void signsEcdsaChallenge(String curve, String algorithm) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(curve));
		KeyPair pair = generator.generateKeyPair();
		ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForKey((ECPublicKey) pair.getPublic());
		byte[] publicKey = verifier.encodePublicKey(pair.getPublic());

		byte[] packet = sign(pair, publicKey, 0);
		TypesReader response = new TypesReader(packet);
		assertEquals(packet.length - 4, response.readUINT32());
		assertEquals(14, response.readByte());
		byte[] signature = response.readByteString();
		assertEquals(0, response.remain());
		assertEquals(algorithm, new TypesReader(signature).readString());
		assertTrue(verifier.verifySignature(CHALLENGE, signature, pair.getPublic()));
		assertFalse(verifier.verifySignature(new byte[]{1}, signature, pair.getPublic()));
	}

	@Test
	public void refusesUnsupportedEcCurve() throws Exception {
		ECPrivateKey privateKey = mock(ECPrivateKey.class);
		EllipticCurve curve = new EllipticCurve(new ECFieldFp(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))),
			BigInteger.ONE, BigInteger.ONE);
		when(privateKey.getParams()).thenReturn(new ECParameterSpec(curve, new ECPoint(BigInteger.ONE, BigInteger.ONE),
			BigInteger.valueOf(3), 1));
		assertArrayEquals(new byte[]{0, 0, 0, 1, 5}, sign(new KeyPair(null, privateKey), new byte[]{1}, 0));
	}
}
