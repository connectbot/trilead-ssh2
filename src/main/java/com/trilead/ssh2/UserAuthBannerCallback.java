package com.trilead.ssh2;

/**
 * A <code>UserAuthBannerCallback</code> is used to receive authentication
 * banners sent by the server.
 *
 * @see Connection#addUserAuthBanner(UserAuthBannerCallback)
 */
public interface UserAuthBannerCallback
{
	/**
	 * Called when the server sends an SSH_MSG_USERAUTH_BANNER packet.
	 * <p>
	 * Note: clients SHOULD use control character filtering as discussed in
	 * RFC4251 to avoid attacks by including terminal control characters in the
	 * fields to be displayed.
	 *
	 * @param banner
	 *            the banner message sent by the server.
	 * @param language
	 *            the language tag sent by the server. This is often empty.
	 */
	void receiveBanner(String banner, String language);
}
