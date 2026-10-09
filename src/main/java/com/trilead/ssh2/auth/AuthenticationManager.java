
package com.trilead.ssh2.auth;

import com.trilead.ssh2.crypto.PublicKeyUtils;
import com.trilead.ssh2.signature.RSASHA256Verify;
import com.trilead.ssh2.signature.RSASHA512Verify;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import com.trilead.ssh2.InteractiveCallback;
import com.trilead.ssh2.UserAuthBannerCallback;
import com.trilead.ssh2.crypto.PEMDecoder;
import com.trilead.ssh2.packets.PacketServiceAccept;
import com.trilead.ssh2.packets.PacketServiceRequest;
import com.trilead.ssh2.packets.PacketUserauthBanner;
import com.trilead.ssh2.packets.PacketUserauthFailure;
import com.trilead.ssh2.packets.PacketUserauthInfoRequest;
import com.trilead.ssh2.packets.PacketUserauthInfoResponse;
import com.trilead.ssh2.packets.PacketUserauthRequestInteractive;
import com.trilead.ssh2.packets.PacketUserauthRequestNone;
import com.trilead.ssh2.packets.PacketUserauthRequestPassword;
import com.trilead.ssh2.packets.PacketUserauthRequestPublicKey;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.ECDSASHA2Verify;
import com.trilead.ssh2.signature.Ed25519Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;
import com.trilead.ssh2.signature.SSHSignature;
import com.trilead.ssh2.signature.SkPublicKey;
import com.trilead.ssh2.transport.MessageHandler;
import com.trilead.ssh2.transport.TransportManager;


/**
 * AuthenticationManager.
 *
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: AuthenticationManager.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class AuthenticationManager implements MessageHandler
{
	TransportManager tm;
	List<UserAuthBannerCallback> bannerCallbacks;

	List<byte[]> packets = new ArrayList<>();
	boolean connectionClosed = false;

	String banner;

	String[] remainingMethods = new String[0];
	boolean isPartialSuccess = false;

	boolean authenticated = false;
	boolean initDone = false;

	public AuthenticationManager(TransportManager tm)
	{
		this(tm, new ArrayList<UserAuthBannerCallback>());
	}

	public AuthenticationManager(TransportManager tm, List<UserAuthBannerCallback> bannerCallbacks)
	{
		this.tm = tm;
		this.bannerCallbacks = bannerCallbacks;
	}

	boolean methodPossible(String methName)
	{
		if (remainingMethods == null)
			return false;

		for (int i = 0; i < remainingMethods.length; i++)
		{
			if (remainingMethods[i].compareTo(methName) == 0)
				return true;
		}
		return false;
	}

	byte[] deQueue() throws IOException
	{
		synchronized (packets)
		{
			while (packets.size() == 0)
			{
				if (connectionClosed)
					throw new IOException("The connection is closed.", tm.getReasonClosedCause());

				try
				{
					packets.wait();
				}
				catch (InterruptedException ign)
				{
				}
			}
			byte[] res = packets.get(0);
			packets.remove(0);
			return res;
		}
	}

	byte[] getNextMessage() throws IOException
	{
		while (true)
		{
			byte[] msg = deQueue();

			if (msg[0] != Packets.SSH_MSG_USERAUTH_BANNER)
				return msg;

			PacketUserauthBanner sb = new PacketUserauthBanner(msg, 0, msg.length);

			banner = sb.getBanner();
			notifyBannerCallbacks(banner, sb.getLanguage());
		}
	}

	private void notifyBannerCallbacks(String message, String language)
	{
		List<UserAuthBannerCallback> callbacks;

		synchronized (bannerCallbacks)
		{
			callbacks = new ArrayList<UserAuthBannerCallback>(bannerCallbacks);
		}

		for (int i = 0; i < callbacks.size(); i++)
		{
			try
			{
				callbacks.get(i).receiveBanner(message, language);
			}
			catch (Exception ignore)
			{
				// Do not let application callback failures break authentication.
			}
		}
	}

	public String[] getRemainingMethods(String user) throws IOException
	{
		initialize(user);
		return remainingMethods;
	}

	public boolean getPartialSuccess()
	{
		return isPartialSuccess;
	}

	private boolean initialize(String user) throws IOException
	{
		if (!initDone)
		{
			tm.registerMessageHandler(this, 0, 255);

			PacketServiceRequest sr = new PacketServiceRequest("ssh-userauth");
			tm.sendMessage(sr.getPayload());

			PacketUserauthRequestNone urn = new PacketUserauthRequestNone("ssh-connection", user);
			tm.sendMessage(urn.getPayload());

			byte[] msg = getNextMessage();
			new PacketServiceAccept(msg, 0, msg.length);
			msg = getNextMessage();

			initDone = true;

			if (msg[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
			{
				authenticated = true;
				tm.removeMessageHandler(this, 0, 255);
				return true;
			}

			if (msg[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
			{
				PacketUserauthFailure puf = new PacketUserauthFailure(msg, 0, msg.length);

				remainingMethods = puf.getAuthThatCanContinue();
				isPartialSuccess = puf.isPartialSuccess();
				return false;
			}

			throw new IOException("Unexpected SSH message (type " + msg[0] + ")");
		}
		return authenticated;
	}

	public boolean authenticatePublicKey(String user, char[] PEMPrivateKey, String password, SecureRandom rnd)
			throws IOException
	{
		KeyPair pair = PEMDecoder.decode(PEMPrivateKey, password);

		return authenticatePublicKey(user, pair, rnd);
	}

	public boolean authenticatePublicKey(String user, KeyPair pair, SecureRandom rnd)
			throws IOException
	{
		return authenticatePublicKey(user, pair, rnd, null);
	}

	public boolean authenticatePublicKey(String user, SignatureProxy signatureProxy)
			throws IOException
	{
		return authenticatePublicKey(user, null, null, signatureProxy);
	}

	public boolean authenticatePublicKey(String user, KeyPair pair, SecureRandom rnd, SignatureProxy signatureProxy)
			throws IOException
	{
		PrivateKey privateKey = null;
		PublicKey publicKey = null;
		if (pair != null)
		{
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
		}
		if (signatureProxy != null)
		{
			publicKey = signatureProxy.getPublicKey();
		}

		try
		{
			initialize(user);

			if (!methodPossible("publickey"))
				throw new IOException("Authentication method publickey not supported by the server at this stage.");

			PublicKeyOffer offer = publicKeyOffer(publicKey);
			byte[] msg = generatePublicKeyUserAuthenticationRequest(user, offer.algorithm, offer.blob);
			byte[] signature;
			if (signatureProxy != null)
				signature = signatureProxy.sign(msg, offer.hashAlgorithm);
			else if (offer.verifier != null)
				signature = offer.verifier.generateSignature(msg, privateKey, rnd);
			else
				throw new IOException("SK key authentication requires a SignatureProxy for signing.");
			if (signature == null)
				throw new IOException("Signing returned no signature.");
			tm.sendMessage(new PacketUserauthRequestPublicKey("ssh-connection", user,
					offer.algorithm, offer.blob, signature).getPayload());

			byte[] ar = getNextMessage();

			return isAuthenticationSuccessful(ar);
		}
		catch (IOException e)
		{
			e.printStackTrace();
			tm.close(e, false);
			throw new IOException("Publickey authentication failed.", e);
		}
	}

	public boolean probePublicKey(String user, PublicKey key) throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("publickey"))
				throw new IOException("Authentication method publickey not supported by the server at this stage.");

			PublicKeyOffer offer = publicKeyOffer(key);
			tm.sendMessage(new PacketUserauthRequestPublicKey("ssh-connection", user,
					offer.algorithm, offer.blob, null).getPayload());

			byte[] reply = getNextMessage();

			if (reply[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
				return isAuthenticationSuccessful(reply);

			TypesReader reader = new TypesReader(reply);
			if (reader.readByte() != Packets.SSH_MSG_USERAUTH_PK_OK)
				throw new IOException("Unexpected reply to public key offer.");

			String algorithm = reader.readString();
			byte[] blob = reader.readByteString();

			if (reader.remain() != 0 || !offer.algorithm.equals(algorithm) || !Arrays.equals(offer.blob, blob))
				throw new IOException("Public key acceptance does not match the offered key.");

			isPartialSuccess = false;
			return true;
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Public key offer failed.", e);
		}
	}

	private PublicKeyOffer publicKeyOffer(PublicKey key) throws IOException
	{
		SSHSignature verifier;
		String hashAlgorithm;
		if (key instanceof DSAPublicKey)
		{
			verifier = DSASHA1Verify.get();
			hashAlgorithm = SignatureProxy.SHA1;
		}
		else if (key instanceof RSAPublicKey)
		{
			Set<String> algorithms = tm.getExtensionInfo().getSignatureAlgorithmsAccepted();
			if (algorithms.contains(RSASHA512Verify.get().getKeyFormat()))
			{
				verifier = RSASHA512Verify.get();
				hashAlgorithm = SignatureProxy.SHA512;
			}
			else if (algorithms.contains(RSASHA256Verify.ID_RSA_SHA_2_256))
			{
				verifier = RSASHA256Verify.get();
				hashAlgorithm = SignatureProxy.SHA256;
			}
			else
			{
				verifier = RSASHA1Verify.get();
				hashAlgorithm = SignatureProxy.SHA1;
			}
		}
		else if (key instanceof ECPublicKey)
		{
			ECPublicKey ecKey = (ECPublicKey) key;
			verifier = ECDSASHA2Verify.getVerifierForKey(ecKey);
			hashAlgorithm = ECDSASHA2Verify.getDigestAlgorithmForParams(ecKey);
		}
		else if (key instanceof SkPublicKey)
		{
			SkPublicKey skKey = (SkPublicKey) key;
			String algorithm = skKey.getSshKeyType();
			return new PublicKeyOffer(algorithm, skKey.getEncoded(), null,
					algorithm.contains("ed25519") ? SignatureProxy.SHA512 : SignatureProxy.SHA256);
		}
		else if (PublicKeyUtils.isEd25519Key(key))
		{
			verifier = Ed25519Verify.get();
			hashAlgorithm = SignatureProxy.SHA512;
		}
		else
			throw new IOException("Unknown public key type.");
		return new PublicKeyOffer(verifier.getKeyFormat(), verifier.encodePublicKey(key), verifier, hashAlgorithm);
	}

	private static class PublicKeyOffer
	{
		final String algorithm;
		final byte[] blob;
		final SSHSignature verifier;
		final String hashAlgorithm;

		PublicKeyOffer(String algorithm, byte[] blob, SSHSignature verifier, String hashAlgorithm)
		{
			this.algorithm = algorithm;
			this.blob = blob;
			this.verifier = verifier;
			this.hashAlgorithm = hashAlgorithm;
		}
	}

	public boolean authenticateNone(String user) throws IOException
	{
		try
		{
			initialize(user);
			return authenticated;
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("None authentication failed.", e);
		}
	}

	public boolean authenticatePassword(String user, String pass) throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("password"))
				throw new IOException("Authentication method password not supported by the server at this stage.");

			PacketUserauthRequestPassword ua = new PacketUserauthRequestPassword("ssh-connection", user, pass);
			tm.sendMessage(ua.getPayload());

			byte[] ar = getNextMessage();

			return isAuthenticationSuccessful(ar);
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Password authentication failed.", e);
		}
	}

	public boolean authenticateInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException
	{
		try
		{
			initialize(user);

			if (!methodPossible("keyboard-interactive"))
				throw new IOException(
						"Authentication method keyboard-interactive not supported by the server at this stage.");

			if (submethods == null)
				submethods = new String[0];

			PacketUserauthRequestInteractive ua = new PacketUserauthRequestInteractive("ssh-connection", user,
					submethods);

			tm.sendMessage(ua.getPayload());

			while (true)
			{
				byte[] ar = getNextMessage();

				if (ar[0] == Packets.SSH_MSG_USERAUTH_INFO_REQUEST)
				{
					PacketUserauthInfoRequest pui = new PacketUserauthInfoRequest(ar, 0, ar.length);

					String[] responses;

					try
					{
						responses = cb.replyToChallenge(pui.getName(), pui.getInstruction(), pui.getNumPrompts(), pui
								.getPrompt(), pui.getEcho());
					}
					catch (Exception e)
					{
						throw new IOException("Exception in callback.", e);
					}

					if (responses == null)
						throw new IOException("Your callback may not return NULL!");

					PacketUserauthInfoResponse puir = new PacketUserauthInfoResponse(responses);
					tm.sendMessage(puir.getPayload());

					continue;
				}

				return isAuthenticationSuccessful(ar);
			}
		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw new IOException("Keyboard-interactive authentication failed.", e);
		}
	}

	public void handleMessage(byte[] msg, int msglen) throws IOException
	{
		synchronized (packets)
		{
			if (msg == null)
			{
				connectionClosed = true;
			}
			else
			{
				byte[] tmp = new byte[msglen];
				System.arraycopy(msg, 0, tmp, 0, msglen);
				packets.add(tmp);
			}

			packets.notifyAll();

			if (packets.size() > 5)
			{
				connectionClosed = true;
				throw new IOException("Error, peer is flooding us with authentication packets.");
			}
		}
	}

	private boolean isAuthenticationSuccessful(byte[] ar) throws IOException
	{
		if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
		{
			authenticated = true;
			tm.removeMessageHandler(this, 0, 255);
			return true;
		}

		if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
		{
			PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

			remainingMethods = puf.getAuthThatCanContinue();
			isPartialSuccess = puf.isPartialSuccess();

			return false;
		}

		throw new IOException("Unexpected SSH message (type " + ar[0] + ")");
	}

	private byte[] generatePublicKeyUserAuthenticationRequest(String user, String algorithm, byte[] publicKeyEncoded) {
		TypesWriter tw = new TypesWriter();
		{
			byte[] H = tm.getSessionIdentifier();

			tw.writeString(H, 0, H.length);
			tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
			tw.writeString(user);
			tw.writeString("ssh-connection");
			tw.writeString("publickey");
			tw.writeBoolean(true);
			tw.writeString(algorithm);
			tw.writeString(publicKeyEncoded, 0, publicKeyEncoded.length);
		}

		return tw.getBytes();
	}
}
