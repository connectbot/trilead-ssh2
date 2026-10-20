
package com.trilead.ssh2;

/**
 * A <code>DHGexParameters</code> object can be used to specify parameters for
 * the diffie-hellman group exchange.
 * <p>
 * Depending on which constructor is used, either the use of a
 * <code>SSH_MSG_KEX_DH_GEX_REQUEST</code> or <code>SSH_MSG_KEX_DH_GEX_REQUEST_OLD</code>
 * can be forced.
 *
 * @see Connection#setDHGexParameters(DHGexParameters)
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: DHGexParameters.java,v 1.1 2007/10/15 12:49:56 cplattne Exp $
 *
 * @deprecated This library is unsupported and receives no further updates, including security fixes.
 * Migrate to <a href="https://github.com/kruton/cbssh">cbssh</a>
 * ({@code org.connectbot.sshlib:sshlib}).
 */

@Deprecated
public class DHGexParameters
{
	private final int min_group_len;
	private final int pref_group_len;
	private final int max_group_len;

	private static final int MIN_ALLOWED = 1024;
	private static final int MAX_ALLOWED = 8192;

	/**
	 * Same as calling {@link #DHGexParameters(int, int, int) DHGexParameters(1024, 2048, 8192)}.
	 * This is also the default used by the Connection class.
	 *
	 */
	public DHGexParameters()
	{
		this(1024, 2048, 8192);
	}

	/**
	 * Estimates the group order for a Diffie-Hellman group that has an
	 * attack complexity approximately the same as O(2**bits).
	 * Values from NIST Special Publication 800-57: Recommendation for Key
	 * Management Part 1 (rev 3) limited by the recommended maximum value
	 * from RFC4419 section 3.
	 *
	 * @param bits the estimated number of bits of security required
	 * @return a DHGexParameters object with the estimated parameters
	 */
	public static DHGexParameters estimate(int bits) {
		int min = 2048;
		int pref = 8192;
		int max = 8192;

		if (bits <= 112) {
			pref = 2048;
		} else if (bits <= 128) {
			pref = 3072;
		} else if (bits <= 192) {
			pref = 7680;
		}

		return new DHGexParameters(min, pref, max);
	}

	/**
	 * This constructor can be used to force the sending of a
	 * <code>SSH_MSG_KEX_DH_GEX_REQUEST_OLD</code> request.
	 * Internally, the minimum and maximum group lengths will
	 * be set to zero.
	 *
	 * @param pref_group_len has to be &gt;= 1024 and &lt;= 8192
	 */
	public DHGexParameters(int pref_group_len)
	{
		if ((pref_group_len < MIN_ALLOWED) || (pref_group_len > MAX_ALLOWED))
			throw new IllegalArgumentException("pref_group_len out of range!");

		this.pref_group_len = pref_group_len;
		this.min_group_len = 0;
		this.max_group_len = 0;
	}

	/**
	 * This constructor can be used to force the sending of a
	 * <code>SSH_MSG_KEX_DH_GEX_REQUEST</code> request.
	 * <p>
	 * Note: older OpenSSH servers don't understand this request, in which
	 * case you should use the {@link #DHGexParameters(int)} constructor.
	 * <p>
	 * All values have to be &gt;= 1024 and &lt;= 8192. Furthermore,
	 * min_group_len &lt;= pref_group_len &lt;= max_group_len.
	 *
	 * @param min_group_len the minimum group length
	 * @param pref_group_len the preferred group length
	 * @param max_group_len the maximum group length
	 */
	public DHGexParameters(int min_group_len, int pref_group_len, int max_group_len)
	{
		if ((min_group_len < MIN_ALLOWED) || (min_group_len > MAX_ALLOWED))
			throw new IllegalArgumentException("min_group_len out of range!");

		if ((pref_group_len < MIN_ALLOWED) || (pref_group_len > MAX_ALLOWED))
			throw new IllegalArgumentException("pref_group_len out of range!");

		if ((max_group_len < MIN_ALLOWED) || (max_group_len > MAX_ALLOWED))
			throw new IllegalArgumentException("max_group_len out of range!");

		if ((pref_group_len < min_group_len) || (pref_group_len > max_group_len))
			throw new IllegalArgumentException("pref_group_len is incompatible with min and max!");

		if (max_group_len < min_group_len)
			throw new IllegalArgumentException("max_group_len must not be smaller than min_group_len!");

		this.min_group_len = min_group_len;
		this.pref_group_len = pref_group_len;
		this.max_group_len = max_group_len;
	}

	/**
	 * Get the maximum group length.
	 *
	 * @return the maximum group length, may be <code>zero</code> if
	 *         SSH_MSG_KEX_DH_GEX_REQUEST_OLD should be requested
	 */
	public int getMax_group_len()
	{
		return max_group_len;
	}

	/**
	 * Get the minimum group length.
	 *
	 * @return minimum group length, may be <code>zero</code> if
	 *         SSH_MSG_KEX_DH_GEX_REQUEST_OLD should be requested
	 */
	public int getMin_group_len()
	{
		return min_group_len;
	}

	/**
	 * Get the preferred group length.
	 *
	 * @return the preferred group length
	 */
	public int getPref_group_len()
	{
		return pref_group_len;
	}
}
