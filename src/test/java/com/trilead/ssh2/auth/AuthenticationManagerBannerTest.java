package com.trilead.ssh2.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;

import com.trilead.ssh2.UserAuthBannerCallback;
import com.trilead.ssh2.packets.PacketUserauthBanner;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.transport.TransportManager;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AuthenticationManagerBannerTest
{
	@Mock
	private TransportManager tm;

	private AuthenticationManager authManager;
	private List<UserAuthBannerCallback> bannerCallbacks;

	@BeforeEach
	public void setUp() throws IOException
	{
		bannerCallbacks = new ArrayList<UserAuthBannerCallback>();
		authManager = new AuthenticationManager(tm, bannerCallbacks);

		lenient().doAnswer(invocation -> null).when(tm).sendMessage(any(byte[].class));
		lenient().doAnswer(invocation -> null).when(tm).registerMessageHandler(any(), any(int.class), any(int.class));
		lenient().doAnswer(invocation -> null).when(tm).removeMessageHandler(any(), any(int.class), any(int.class));
	}

	@Test
	public void authenticateNone_NotifiesBannerCallbackBeforeFailure() throws Exception
	{
		RecordingBannerCallback callback = new RecordingBannerCallback();
		bannerCallbacks.add(callback);

		queueMessages(
				new byte[] { Packets.SSH_MSG_SERVICE_ACCEPT },
				new PacketUserauthBanner("Visit https://login.tailscale.com/a/abc123", "en-US").getPayload(),
				createUserauthFailure(new String[] { "publickey" }));

		assertFalse(authManager.authenticateNone("testuser"));
		assertEquals("Visit https://login.tailscale.com/a/abc123", callback.banner);
		assertEquals("en-US", callback.language);
		assertEquals(1, callback.calls);
	}

	@Test
	public void authenticateNone_IgnoresBannerCallbackException() throws Exception
	{
		bannerCallbacks.add((banner, language) -> {
			throw new IllegalStateException("callback failed");
		});

		queueMessages(
				new byte[] { Packets.SSH_MSG_SERVICE_ACCEPT },
				new PacketUserauthBanner("Login required", "").getPayload(),
				createUserauthFailure(new String[] { "password" }));

		assertFalse(authManager.authenticateNone("testuser"));
	}

	private void queueMessages(byte[]... messages)
			throws IOException
	{
		for (byte[] message : messages)
		{
			authManager.handleMessage(message, message.length);
		}
	}

	private byte[] createUserauthFailure(String[] methods)
	{
		TypesWriter tw = new TypesWriter();
		StringBuilder methodList = new StringBuilder();

		for (int i = 0; i < methods.length; i++)
		{
			if (i > 0)
				methodList.append(",");
			methodList.append(methods[i]);
		}

		tw.writeByte(Packets.SSH_MSG_USERAUTH_FAILURE);
		tw.writeString(methodList.toString());
		tw.writeBoolean(false);

		return tw.getBytes();
	}

	private static class RecordingBannerCallback implements UserAuthBannerCallback
	{
		String banner;
		String language;
		int calls;

		@Override
		public void receiveBanner(String banner, String language)
		{
			this.banner = banner;
			this.language = language;
			calls++;
		}
	}
}
