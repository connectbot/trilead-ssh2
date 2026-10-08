/*
 * Copyright 2007 Kenny Root, Jeffrey Sharkey
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

package com.trilead.ssh2.channel;

import com.trilead.ssh2.signature.RSASHA256Verify;
import com.trilead.ssh2.signature.RSASHA512Verify;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;
import java.util.Map.Entry;

import com.trilead.ssh2.AuthAgentCallback;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;

/**
 * AuthAgentForwardThread.
 *
 * @author Kenny Root
 * @version $Id$
 */
public class AuthAgentForwardThread extends Thread implements IChannelWorkerThread
{
	private static final byte[] SSH_AGENT_FAILURE = {0, 0, 0, 1, 5}; // 5
	private static final byte[] SSH_AGENT_SUCCESS = {0, 0, 0, 1, 6}; // 6

	private static final int SSH2_AGENTC_REQUEST_IDENTITIES = 11;
	private static final int SSH2_AGENT_IDENTITIES_ANSWER = 12;

	private static final int SSH2_AGENTC_SIGN_REQUEST = 13;
	private static final int SSH2_AGENT_SIGN_RESPONSE = 14;

	private static final int SSH2_AGENTC_ADD_IDENTITY = 17;
	private static final int SSH2_AGENTC_REMOVE_IDENTITY = 18;
	private static final int SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;

//	private static final int SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
//	private static final int SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;

	private static final int SSH_AGENTC_LOCK = 22;
	private static final int SSH_AGENTC_UNLOCK = 23;

	private static final int SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;
//	private static final int SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

	// Constraints for adding keys
	private static final int SSH_AGENT_CONSTRAIN_LIFETIME = 1;
	private static final int SSH_AGENT_CONSTRAIN_CONFIRM = 2;

	// Flags for signature requests
//	private static final int SSH_AGENT_OLD_SIGNATURE = 1;
	// https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-7.3
	private static final int SSH_AGENT_RSA_SHA2_256 = 0x02;
	private static final int SSH_AGENT_RSA_SHA2_512 = 0x04;

	private static final Logger log = Logger.getLogger(RemoteAcceptThread.class);

	AuthAgentCallback authAgent;
	OutputStream os;
	InputStream is;
	Channel c;

	byte[] buffer = new byte[Channel.CHANNEL_BUFFER_SIZE];

	public AuthAgentForwardThread(Channel c, AuthAgentCallback authAgent)
	{
		this.c = c;
		this.authAgent = authAgent;

		if (log.isEnabled())
			log.log(20, "AuthAgentForwardThread started");
	}

	@Override
	public void run()
	{
		try
		{
			c.cm.registerThread(this);
		}
		catch (IOException e)
		{
			stopWorking();
			return;
		}

		try
		{
			c.cm.sendOpenConfirmation(c);

			is = c.getStdoutStream();
			os = c.getStdinStream();

			int totalSize = 4;
			int readSoFar = 0;

			while (true) {
				int len;

				try
				{
					len = is.read(buffer, readSoFar, buffer.length - readSoFar);
				}
				catch (IOException e)
				{
					stopWorking();
					return;
				}

				if (len <= 0)
					break;

				readSoFar += len;

				if (readSoFar >= 4) {
					TypesReader tr = new TypesReader(buffer, 0, 4);
					totalSize = tr.readUINT32() + 4;
				}

				if (totalSize == readSoFar) {
					TypesReader tr = new TypesReader(buffer, 4, readSoFar - 4);
					int messageType = tr.readByte();

					switch (messageType) {
					case SSH2_AGENTC_REQUEST_IDENTITIES:
						sendIdentities();
						break;
					case SSH2_AGENTC_ADD_IDENTITY:
						addIdentity(tr, false);
						break;
					case SSH2_AGENTC_ADD_ID_CONSTRAINED:
						addIdentity(tr, true);
						break;
					case SSH2_AGENTC_REMOVE_IDENTITY:
						removeIdentity(tr);
						break;
					case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
						removeAllIdentities(tr);
						break;
					case SSH2_AGENTC_SIGN_REQUEST:
						processSignRequest(tr);
						break;
					case SSH_AGENTC_LOCK:
						processLockRequest(tr);
						break;
					case SSH_AGENTC_UNLOCK:
						processUnlockRequest(tr);
						break;
					default:
						os.write(SSH_AGENT_FAILURE);
						break;
					}

					readSoFar = 0;
				}
			}

			c.cm.closeChannel(c, "EOF on both streams reached.", true);
		}
		catch (IOException e)
		{
			log.log(50, "IOException in agent forwarder: " + e.getMessage());

			try
			{
				is.close();
			}
			catch (IOException e1)
			{
			}

			try
			{
				os.close();
			}
			catch (IOException e2)
			{
			}

			try
			{
				c.cm.closeChannel(c, "IOException in agent forwarder (" + e.getMessage() + ")", true);
			}
			catch (IOException e3)
			{
			}
		}
	}

	public void stopWorking() {
		try
		{
			/* This will lead to an IOException in the is.read() call */
			is.close();
		}
		catch (IOException e)
		{
		}
	}

	/**
	 * @return whether the agent is locked
	 */
	private boolean failWhenLocked() throws IOException
	{
		if (authAgent.isAgentLocked()) {
			os.write(SSH_AGENT_FAILURE);
			return true;
		} else
			return false;
	}

	private void sendIdentities() throws IOException
	{
		Map<String, byte[]> keys = null;

		TypesWriter tw = new TypesWriter();
		tw.writeByte(SSH2_AGENT_IDENTITIES_ANSWER);
		int numKeys = 0;

		if (!authAgent.isAgentLocked())
			keys = authAgent.retrieveIdentities();

		if (keys != null)
			numKeys = keys.size();

		tw.writeUINT32(numKeys);

		if (keys != null) {
			for (Entry<String, byte[]> entry : keys.entrySet()) {
				byte[] keyBytes = entry.getValue();
				tw.writeString(keyBytes, 0, keyBytes.length);
				tw.writeString(entry.getKey());
			}
		}

		sendPacket(tw.getBytes());
	}

	/**
	 * @param tr
	 */
	private void addIdentity(TypesReader tr, boolean checkConstraints) {
		try
		{
			if (failWhenLocked())
				return;

			String type = tr.readString();

			String comment;
			String keyType;
			KeySpec pubSpec;
			KeySpec privSpec;

			if (type.equals("ssh-rsa")) {
				keyType = "RSA";

				BigInteger n = tr.readMPINT();
				BigInteger e = tr.readMPINT();
				BigInteger d = tr.readMPINT();
				BigInteger iqmp = tr.readMPINT();
				BigInteger p = tr.readMPINT();
				BigInteger q = tr.readMPINT();
				comment = tr.readString();

				// Derive the extra values Java needs.
				BigInteger dmp1 = d.mod(p.subtract(BigInteger.ONE));
				BigInteger dmq1 = d.mod(q.subtract(BigInteger.ONE));

				pubSpec = new RSAPublicKeySpec(n, e);
				privSpec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dmp1, dmq1, iqmp);
			} else if (type.equals(DSASHA1Verify.ID_SSH_DSS)) {
				keyType = "DSA";

				BigInteger p = tr.readMPINT();
				BigInteger q = tr.readMPINT();
				BigInteger g = tr.readMPINT();
				BigInteger y = tr.readMPINT();
				BigInteger x = tr.readMPINT();
				comment = tr.readString();

				pubSpec = new DSAPublicKeySpec(y, p, q, g);
				privSpec = new DSAPrivateKeySpec(x, p, q, g);
			} else if (type.equals(ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get().getKeyFormat())) {
				ECDSASHA2Verify verifier = ECDSASHA2Verify.ECDSASHA2NISTP256Verify.get();
				keyType = "EC";

				String curveName = tr.readString();
				byte[] groupBytes = tr.readByteString();
				BigInteger exponent = tr.readMPINT();
				comment = tr.readString();

				if (!"nistp256".equals(curveName)) {
					log.log(2, "Invalid curve name for ecdsa-sha2-nistp256: " + curveName);
					os.write(SSH_AGENT_FAILURE);
					return;
				}

				ECParameterSpec params = verifier.getParameterSpec();
				ECPoint group = verifier.decodeECPoint(groupBytes);
				if (group == null) {
					// TODO log error
					os.write(SSH_AGENT_FAILURE);
					return;
				}

				pubSpec = new ECPublicKeySpec(group, params);
				privSpec = new ECPrivateKeySpec(exponent, params);
			} else {
				log.log(2, "Unknown key type: " + type);
				os.write(SSH_AGENT_FAILURE);
				return;
			}

			PublicKey pubKey;
			PrivateKey privKey;
			try {
				KeyFactory kf = KeyFactory.getInstance(keyType);
				pubKey = kf.generatePublic(pubSpec);
				privKey = kf.generatePrivate(privSpec);
			} catch (NoSuchAlgorithmException ex) {
				// TODO: log error
				os.write(SSH_AGENT_FAILURE);
				return;
			} catch (InvalidKeySpecException ex) {
				// TODO: log error
				os.write(SSH_AGENT_FAILURE);
				return;
			}

			KeyPair pair = new KeyPair(pubKey, privKey);

			boolean confirmUse = false;
			int lifetime = 0;

			if (checkConstraints) {
				while (tr.remain() > 0) {
					int constraint = tr.readByte();
					if (constraint == SSH_AGENT_CONSTRAIN_CONFIRM)
						confirmUse = true;
					else if (constraint == SSH_AGENT_CONSTRAIN_LIFETIME)
						lifetime = tr.readUINT32();
					else {
						// Unknown constraint. Bail.
						os.write(SSH_AGENT_FAILURE);
						return;
					}
				}
			}

			if (authAgent.addIdentity(pair, comment, confirmUse, lifetime))
				os.write(SSH_AGENT_SUCCESS);
			else
				os.write(SSH_AGENT_FAILURE);
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	/**
	 * @param tr
	 */
	private void removeIdentity(TypesReader tr) {
		try
		{
			if (failWhenLocked())
				return;

			byte[] publicKey = tr.readByteString();
			if (authAgent.removeIdentity(publicKey))
				os.write(SSH_AGENT_SUCCESS);
			else
				os.write(SSH_AGENT_FAILURE);
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	/**
	 * @param tr
	 */
	private void removeAllIdentities(TypesReader tr) {
		try
		{
			if (failWhenLocked())
				return;

			if (authAgent.removeAllIdentities())
				os.write(SSH_AGENT_SUCCESS);
			else
				os.write(SSH_AGENT_FAILURE);
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	private void processSignRequest(TypesReader tr)
	{
		try
		{
			if (failWhenLocked())
				return;

			byte[] publicKeyBytes = tr.readByteString();
			byte[] challenge = tr.readByteString();

			int flags = tr.readUINT32();

			if ((flags & ~SSH_AGENT_RSA_SHA2_512 & ~SSH_AGENT_RSA_SHA2_256) != 0) {
				// We don't understand these flags; abort!
				log.log(2, "Unrecognized ssh-agent flags: " + flags);
				os.write(SSH_AGENT_FAILURE);
				return;
			}

			KeyPair pair = authAgent.getKeyPair(publicKeyBytes);

			if (pair == null) {
				os.write(SSH_AGENT_FAILURE);
				return;
			}

			byte[] response;

			PrivateKey privKey = pair.getPrivate();
			if (privKey instanceof RSAPrivateKey) {
				RSAPrivateKey rsaPrivKey = (RSAPrivateKey) privKey;
				if ((flags & SSH_AGENT_RSA_SHA2_512) != 0) {
					response = RSASHA512Verify.get().generateSignature(challenge, rsaPrivKey, new SecureRandom());
				} else if ((flags & SSH_AGENT_RSA_SHA2_256) != 0) {
					response = RSASHA256Verify.get().generateSignature(challenge, rsaPrivKey, new SecureRandom());
				} else {
					response = RSASHA1Verify.get().generateSignature(challenge, rsaPrivKey, new SecureRandom());
				}
			} else if (privKey instanceof DSAPrivateKey) {
				response = DSASHA1Verify.get().generateSignature(challenge, privKey, new SecureRandom());
			} else if (privKey instanceof ECPrivateKey) {
				ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForKey((ECPrivateKey) privKey);
				if (verifier == null) {
					os.write(SSH_AGENT_FAILURE);
					return;
				}
				response = verifier.generateSignature(challenge, privKey, new SecureRandom());
			} else if (privKey instanceof Ed25519PrivateKey) {
				response = Ed25519Verify.get().generateSignature(challenge, privKey, new SecureRandom());
			} else {
				os.write(SSH_AGENT_FAILURE);
				return;
			}

			TypesWriter tw = new TypesWriter();
			tw.writeByte(SSH2_AGENT_SIGN_RESPONSE);
			tw.writeString(response, 0, response.length);

			sendPacket(tw.getBytes());
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	/**
	 * @param tr
	 */
	private void processLockRequest(TypesReader tr) {
		try
		{
			if (failWhenLocked())
				return;

			String lockPassphrase = tr.readString();
			if (!authAgent.setAgentLock(lockPassphrase)) {
				os.write(SSH_AGENT_FAILURE);
				return;
			} else
				os.write(SSH_AGENT_SUCCESS);
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	/**
	 * @param tr
	 */
	private void processUnlockRequest(TypesReader tr)
	{
		try
		{
			String unlockPassphrase = tr.readString();

			if (authAgent.requestAgentUnlock(unlockPassphrase))
				os.write(SSH_AGENT_SUCCESS);
			else
				os.write(SSH_AGENT_FAILURE);
		}
		catch (IOException e)
		{
			try
			{
				os.write(SSH_AGENT_FAILURE);
			}
			catch (IOException e1)
			{
			}
		}
	}

	/**
	 * @param message
	 * @throws IOException on error
	 */
	private void sendPacket(byte[] message) throws IOException
	{
		TypesWriter packet = new TypesWriter();
		packet.writeUINT32(message.length);
		packet.writeBytes(message);
		os.write(packet.getBytes());
	}
}
