
package com.trilead.ssh2.auth;

import com.trilead.ssh2.crypto.PublicKeyUtils;
import com.trilead.ssh2.crypto.keys.Ed25519PrivateKey;
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
import java.util.List;
import java.util.Set;

import com.trilead.ssh2.InteractiveCallback;
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

	List<byte[]> packets = new ArrayList<>();
	boolean connectionClosed = false;

	List<String> banners = new ArrayList<>();

	String[] remainingMethods = new String[0];
	boolean isPartialSuccess = false;

	boolean authenticated = false;
	boolean initDone = false;

	public AuthenticationManager(TransportManager tm)
	{
		this.tm = tm;
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

			synchronized (banners)
			{
				banners.add(sb.getBanner());
			}
		}
	}

	/**
	 * Returns the {@code SSH_MSG_USERAUTH_BANNER} messages sent by the server.
	 * The server may send banners at any point before authentication completes
	 * (typically used to display login notices or, in the case of Tailscale SSH,
	 * a web URL the user must visit to finish authenticating).
	 * <p>
	 * Returns a defensive snapshot, so the caller is free to iterate without
	 * holding any locks. Synchronizes only on the {@code banners} list itself,
	 * NOT on the {@code AuthenticationManager} or {@code Connection} monitor,
	 * so it remains callable from another thread while a blocking
	 * {@code authenticateWith*} call is in progress.
	 *
	 * @return list of banner strings in the order received, never {@code null};
	 *         empty if the server has not sent any.
	 */
	public List<String> getBanners()
	{
		synchronized (banners)
		{
			return new ArrayList<>(banners);
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

			if (publicKey instanceof DSAPublicKey)
			{
				SSHSignature s = DSASHA1Verify.get();
				byte[] pk_enc = s.encodePublicKey(publicKey);

				byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, DSASHA1Verify.ID_SSH_DSS, pk_enc);

				byte[] ds_enc;
				if (signatureProxy != null)
				{
					ds_enc = signatureProxy.sign(msg, SignatureProxy.SHA1);
				}
				else
				{
					ds_enc = s.generateSignature(msg, privateKey, rnd);
				}

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						DSASHA1Verify.ID_SSH_DSS, pk_enc, ds_enc);
				tm.sendMessage(ua.getPayload());
			}
			else if (publicKey instanceof RSAPublicKey)
			{
				byte[] pk_enc = RSASHA1Verify.get().encodePublicKey(publicKey);
				String pk_algorithm;


				// Servers support different hash algorithms for RSA keys
				// https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-12
				Set<String> algsAccepted = tm.getExtensionInfo().getSignatureAlgorithmsAccepted();
				final byte[] rsa_sig_enc;

				if (algsAccepted.contains(RSASHA512Verify.get().getKeyFormat()))
				{
					SSHSignature s = RSASHA512Verify.get();
					pk_algorithm = s.getKeyFormat();
					byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, pk_algorithm, pk_enc);
					if (signatureProxy != null)
					{
						rsa_sig_enc = signatureProxy.sign(msg, SignatureProxy.SHA512);
					}
					else
					{
						rsa_sig_enc = s.generateSignature(msg, privateKey, rnd);
					}
				}
				else if (algsAccepted.contains(RSASHA256Verify.ID_RSA_SHA_2_256))
				{
					pk_algorithm = RSASHA256Verify.ID_RSA_SHA_2_256;
					byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, pk_algorithm, pk_enc);

					if (signatureProxy != null)
					{
						rsa_sig_enc = signatureProxy.sign(msg, SignatureProxy.SHA256);
					}
					else
					{
						rsa_sig_enc = RSASHA256Verify.get().generateSignature(msg, privateKey, rnd);
					}
				}
				else
				{
					pk_algorithm = "ssh-rsa";
					byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, pk_algorithm, pk_enc);
					if (signatureProxy != null)
					{
						rsa_sig_enc = signatureProxy.sign(msg, SignatureProxy.SHA1);
					}
					else
					{
						// Server always accepts RSA with SHA1
						rsa_sig_enc = RSASHA1Verify.get().generateSignature(msg, privateKey, rnd);
					}
				}

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						pk_algorithm, pk_enc, rsa_sig_enc);

				tm.sendMessage(ua.getPayload());
			}
			else if (publicKey instanceof ECPublicKey)
			{
				ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

				ECDSASHA2Verify verifier = ECDSASHA2Verify.getVerifierForKey(ecPublicKey);

				final String algo = verifier.getKeyFormat();

				byte[] pk_enc = verifier.encodePublicKey(ecPublicKey);

				byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, algo, pk_enc);

				byte[] ec_sig_enc;
				if (signatureProxy != null)
				{
					ec_sig_enc = signatureProxy.sign(msg, ECDSASHA2Verify.getDigestAlgorithmForParams(ecPublicKey));
				}
				else
				{
					ec_sig_enc = verifier.generateSignature(msg, privateKey, rnd);
				}

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						algo, pk_enc, ec_sig_enc);

				tm.sendMessage(ua.getPayload());
			}
			else if (publicKey instanceof SkPublicKey)
			{
				// FIDO2 Security Key (SK) authentication
				// This check must come before the Ed25519 check because
				// SK Ed25519 keys match isEd25519Key() but require SK-specific encoding.
				if (signatureProxy == null)
				{
					throw new IOException("SK key authentication requires a SignatureProxy for signing.");
				}

				SkPublicKey skPublicKey = (SkPublicKey) publicKey;
				final String algo = skPublicKey.getSshKeyType();

				// Get the encoded public key (includes key type, key data, and application)
				byte[] pk_enc = skPublicKey.getEncoded();

				byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, algo, pk_enc);

				// Determine the hash algorithm based on key type
				// sk-ssh-ed25519@openssh.com uses SHA512 (same as Ed25519)
				// sk-ecdsa-sha2-nistp256@openssh.com uses SHA256
				String hashAlgorithm;
				if (algo.contains("ed25519"))
				{
					hashAlgorithm = SignatureProxy.SHA512;
				}
				else
				{
					hashAlgorithm = SignatureProxy.SHA256;
				}

				// The SignatureProxy.sign() for SK keys must return the complete
				// signature blob including flags and counter, not just the raw signature
				byte[] sk_sig_enc = signatureProxy.sign(msg, hashAlgorithm);

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						algo, pk_enc, sk_sig_enc);

				tm.sendMessage(ua.getPayload());
			}
			else if (PublicKeyUtils.isEd25519Key(publicKey))
			{
				final String algo = Ed25519Verify.ED25519_ID;

				byte[] pk_enc = Ed25519Verify.get().encodePublicKey(publicKey);

				byte[] msg = this.generatePublicKeyUserAuthenticationRequest(user, algo, pk_enc);

				byte[] ed_sig_enc;
				if (signatureProxy != null)
				{
					ed_sig_enc = signatureProxy.sign(msg, SignatureProxy.SHA512);
				}
				else
				{
					Ed25519PrivateKey pk = Ed25519Verify.convertPrivateKey(privateKey);
					ed_sig_enc = Ed25519Verify.get().generateSignature(msg, pk, rnd);
				}

				PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
						algo, pk_enc, ed_sig_enc);

				tm.sendMessage(ua.getPayload());
			}
			else
			{
				throw new IOException("Unknown public key type.");
			}

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
