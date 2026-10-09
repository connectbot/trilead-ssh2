/*
 * Copyright 2026 Kenny Root
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * a.) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * b.) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * c.) Neither the name of Trilead nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.trilead.ssh2.auth;

import com.trilead.ssh2.ExtensionInfo;
import com.trilead.ssh2.crypto.PublicKeyUtils;
import com.trilead.ssh2.packets.PacketUserauthBanner;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.transport.TransportManager;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthenticationManagerProbeTest {
	private TransportManager transport;
	private AuthenticationManager manager;
	private final List<byte[]> sent = new ArrayList<>();

	@BeforeEach
	void setup() throws Exception {
		transport = mock(TransportManager.class);
		manager = new AuthenticationManager(transport);
		manager.initDone = true;
		manager.remainingMethods = new String[] { "publickey" };
		ExtensionInfo extension = mock(ExtensionInfo.class);
		when(extension.getSignatureAlgorithmsAccepted()).thenReturn(Set.of("rsa-sha2-512"));
		when(transport.getExtensionInfo()).thenReturn(extension);
		when(transport.getSessionIdentifier()).thenReturn(new byte[] { 1, 2, 3 });
		doAnswer(call -> { sent.add(call.getArgument(0)); return null; }).when(transport).sendMessage(any(byte[].class));
	}

	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "Ed25519", "DSA" })
	void probeAndSignatureHaveSameAlgorithmAndKey(String type) throws Exception {
		KeyPair key = key(type);
		String algorithm = algorithm(type);
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(key.getPublic());
		queue(acceptance(algorithm, blob));
		assertTrue(manager.probePublicKey("alice", key.getPublic()));
		assertFalse(manager.authenticated);
		assertFalse(manager.getPartialSuccess());
		TypesReader probe = request(sent.get(0));
		assertFalse(probe.readBoolean());
		assertEquals(algorithm, probe.readString());
		assertArrayEquals(blob, probe.readByteString());
		assertEquals(0, probe.remain());

		SignatureProxy signer = mock(SignatureProxy.class);
		when(signer.getPublicKey()).thenReturn(key.getPublic());
		when(signer.sign(any(byte[].class), any(String.class))).thenReturn(new byte[] { 9 });
		queue(new byte[] { Packets.SSH_MSG_USERAUTH_SUCCESS });
		assertTrue(manager.authenticatePublicKey("alice", signer));
		TypesReader signed = request(sent.get(1));
		assertTrue(signed.readBoolean());
		assertEquals(algorithm, signed.readString());
		assertArrayEquals(blob, signed.readByteString());
		assertArrayEquals(new byte[] { 9 }, signed.readByteString());
		assertEquals(0, signed.remain());
		verify(signer, times(1)).sign(any(byte[].class), any(String.class));
	}

	@Test
	void rejectionUpdatesMethodsWithoutClosingTransport() throws Exception {
		KeyPair key = key("EC");
		queue(failure("password", false));
		assertFalse(manager.probePublicKey("alice", key.getPublic()));
		assertArrayEquals(new String[] { "password" }, manager.getRemainingMethods("alice"));
		assertFalse(manager.authenticated);
		verify(transport, never()).close(any(), anyBoolean());
	}

	@Test
	void mismatchedAlgorithmClosesTransport() throws Exception {
		KeyPair key = key("EC");
		queue(acceptance("ssh-rsa", PublicKeyUtils.extractPublicKeyBlob(key.getPublic())));
		assertThrows(IOException.class, () -> manager.probePublicKey("alice", key.getPublic()));
		verify(transport).close(any(IOException.class), eq(false));
	}

	@Test
	void mismatchedKeyClosesTransport() throws Exception {
		KeyPair key = key("EC");
		queue(acceptance(algorithm("EC"), PublicKeyUtils.extractPublicKeyBlob(key("EC").getPublic())));
		assertThrows(IOException.class, () -> manager.probePublicKey("alice", key.getPublic()));
		verify(transport).close(any(IOException.class), eq(false));
	}

	@Test
	void malformedReplyClosesTransport() throws Exception {
		queue(new byte[] { Packets.SSH_MSG_USERAUTH_PK_OK });
		assertThrows(IOException.class, () -> manager.probePublicKey("alice", key("EC").getPublic()));
		verify(transport).close(any(IOException.class), eq(false));
	}

	@Test
	void unexpectedSuccessDoesNotAuthenticateProbe() throws Exception {
		queue(new byte[] { Packets.SSH_MSG_USERAUTH_SUCCESS });
		assertThrows(IOException.class, () -> manager.probePublicKey("alice", key("EC").getPublic()));
		assertFalse(manager.authenticated);
	}

	@Test
	void bannersAreDeliveredWhileWaitingForAcceptance() throws Exception {
		List<String> banners = new ArrayList<>();
		manager.bannerCallbacks.add((message, language) -> banners.add(message));
		KeyPair key = key("EC");
		queue(new PacketUserauthBanner("hello", "en").getPayload());
		queue(acceptance(algorithm("EC"), PublicKeyUtils.extractPublicKeyBlob(key.getPublic())));
		assertTrue(manager.probePublicKey("alice", key.getPublic()));
		assertEquals(List.of("hello"), banners);
	}

	@ParameterizedTest
	@ValueSource(strings = { "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa" })
	void rsaProbeAndSignatureUseNegotiatedAlgorithm(String algorithm) throws Exception {
		when(transport.getExtensionInfo().getSignatureAlgorithmsAccepted()).thenReturn(Set.of(algorithm));
		KeyPair key = key("RSA");
		byte[] blob = PublicKeyUtils.extractPublicKeyBlob(key.getPublic());
		queue(acceptance(algorithm, blob));
		assertTrue(manager.probePublicKey("alice", key.getPublic()));
		queue(new byte[] { Packets.SSH_MSG_USERAUTH_SUCCESS });
		assertTrue(manager.authenticatePublicKey("alice", key, new java.security.SecureRandom()));
		TypesReader signed = request(sent.get(1));
		assertTrue(signed.readBoolean());
		assertEquals(algorithm, signed.readString());
		assertArrayEquals(blob, signed.readByteString());
		assertTrue(signed.readByteString().length > 0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com" })
	void securityKeyProbeUsesSecurityKeyBlob(String algorithm) throws Exception {
		AuthenticationManagerSkKeyTest.TestSkPublicKey key = new AuthenticationManagerSkKeyTest.TestSkPublicKey(
				algorithm, "ssh:", new byte[32]);
		queue(acceptance(algorithm, key.getEncoded()));
		assertTrue(manager.probePublicKey("alice", key));
		TypesReader probe = request(sent.get(0));
		assertFalse(probe.readBoolean());
		assertEquals(algorithm, probe.readString());
		assertArrayEquals(key.getEncoded(), probe.readByteString());
		assertEquals(0, probe.remain());
	}

	@Test
	void missingSignatureDoesNotBecomeUnsignedAuthenticationRequest() throws Exception {
		SignatureProxy signer = mock(SignatureProxy.class);
		when(signer.getPublicKey()).thenReturn(key("EC").getPublic());
		assertThrows(IOException.class, () -> manager.authenticatePublicKey("alice", signer));
		assertTrue(sent.isEmpty());
		verify(transport).close(any(IOException.class), eq(false));
	}

	private void queue(byte[] message) throws IOException {
		manager.handleMessage(message, message.length);
	}

	private static KeyPair key(String type) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(type);
		if (type.equals("RSA") || type.equals("DSA")) generator.initialize(1024);
		if (type.equals("EC")) generator.initialize(256);
		return generator.generateKeyPair();
	}

	private static String algorithm(String type) {
		return switch (type) {
			case "RSA" -> "rsa-sha2-512";
			case "EC" -> "ecdsa-sha2-nistp256";
			case "Ed25519" -> "ssh-ed25519";
			default -> "ssh-dss";
		};
	}

	private static TypesReader request(byte[] message) throws IOException {
		TypesReader reader = new TypesReader(message);
		assertEquals(Packets.SSH_MSG_USERAUTH_REQUEST, reader.readByte());
		assertEquals("alice", reader.readString());
		assertEquals("ssh-connection", reader.readString());
		assertEquals("publickey", reader.readString());
		return reader;
	}

	private static byte[] acceptance(String algorithm, byte[] blob) {
		TypesWriter writer = new TypesWriter();
		writer.writeByte(Packets.SSH_MSG_USERAUTH_PK_OK);
		writer.writeString(algorithm);
		writer.writeString(blob, 0, blob.length);
		return writer.getBytes();
	}

	private static byte[] failure(String methods, boolean partial) {
		TypesWriter writer = new TypesWriter();
		writer.writeByte(Packets.SSH_MSG_USERAUTH_FAILURE);
		writer.writeString(methods);
		writer.writeBoolean(partial);
		return writer.getBytes();
	}
}
