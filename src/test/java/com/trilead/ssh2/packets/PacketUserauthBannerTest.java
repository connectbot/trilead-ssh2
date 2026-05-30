package com.trilead.ssh2.packets;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import org.junit.jupiter.api.Test;

public class PacketUserauthBannerTest
{
	@Test
	public void parsesBannerLanguage() throws IOException
	{
		PacketUserauthBanner packet = new PacketUserauthBanner("Login required", "en-US");
		PacketUserauthBanner parsed = new PacketUserauthBanner(packet.getPayload(), 0, packet.getPayload().length);

		assertEquals("Login required", parsed.getBanner());
		assertEquals("en-US", parsed.getLanguage());
	}
}
