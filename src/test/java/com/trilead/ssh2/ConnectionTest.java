package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ConnectionTest {

private Connection connection;

@BeforeEach
public void setUp() {
	connection = new Connection("testhost.example.com", 2222);
}

@Test
public void testConnectionConstructorWithHostnameAndPort() {
	String hostname = "example.com";
	int port = 2222;

	Connection conn = new Connection(hostname, port);

	assertEquals(hostname,
				conn.getHostname(), "Hostname should match constructor parameter");
	assertEquals(port,
				conn.getPort(), "Port should match constructor parameter");
}

@Test
public void testConnectionConstructorWithHostnameOnly() {
	String hostname = "example.com";

	Connection conn = new Connection(hostname);

	assertEquals(hostname,
				conn.getHostname(), "Hostname should match constructor parameter");
	assertEquals(22, conn.getPort(), "Port should default to 22");
}

@Test
public void testGetHostname() {
	assertEquals("testhost.example.com", connection.getHostname(), "Should return hostname passed to constructor");
}

@Test
public void testGetPort() {
	assertEquals(2222,
				connection.getPort(), "Should return port passed to constructor");
}

@Test
public void testIsAuthenticationCompleteInitiallyFalse() {
	assertFalse(connection.isAuthenticationComplete(), "Authentication should initially be incomplete");
}

@Test
public void testIsAuthenticationPartialSuccessInitiallyFalse() {
	assertFalse(connection.isAuthenticationPartialSuccess(), "Partial success should initially be false");
}

@Test
public void testGetAvailableCiphers() {
	String[] ciphers = Connection.getAvailableCiphers();

	assertNotNull(ciphers, "Cipher list should not be null");
	assertTrue(ciphers.length > 0, "Should have at least one cipher available");

	// Check that all returned values are non-null strings
	for (String cipher : ciphers) {
	assertNotNull(cipher, "Cipher name should not be null");
	assertTrue(cipher.length() > 0, "Cipher name should not be empty");
	}
}

@Test
public void testGetAvailableMACs() {
	String[] macs = Connection.getAvailableMACs();

	assertNotNull(macs, "MAC list should not be null");
	assertTrue(macs.length > 0, "Should have at least one MAC available");

	// Check that all returned values are non-null strings
	for (String mac : macs) {
	assertNotNull(mac, "MAC name should not be null");
	assertTrue(mac.length() > 0, "MAC name should not be empty");
	}
}

@Test
public void testGetAvailableServerHostKeyAlgorithms() {
	String[] algorithms = Connection.getAvailableServerHostKeyAlgorithms();

	assertNotNull(algorithms, "Algorithm list should not be null");
	assertTrue(algorithms.length > 0, "Should have at least one algorithm available");

	// Check that all returned values are non-null strings
	for (String algorithm : algorithms) {
	assertNotNull(algorithm, "Algorithm name should not be null");
	assertTrue(algorithm.length() > 0, "Algorithm name should not be empty");
	}
}

@Test
public void testStaticMethodsReturnSameResults() {
	// Static methods should return consistent results across calls
	String[] ciphers1 = Connection.getAvailableCiphers();
	String[] ciphers2 = Connection.getAvailableCiphers();

	assertArrayEquals(ciphers1, ciphers2, "Cipher lists should be identical");

	String[] macs1 = Connection.getAvailableMACs();
	String[] macs2 = Connection.getAvailableMACs();

	assertArrayEquals(macs1, macs2, "MAC lists should be identical");

	String[] algos1 = Connection.getAvailableServerHostKeyAlgorithms();
	String[] algos2 = Connection.getAvailableServerHostKeyAlgorithms();

	assertArrayEquals(algos1, algos2, "Algorithm lists should be identical");
}

@Test
public void testSetSecureRandom() {
	SecureRandom customRandom = new SecureRandom();

	// This should not throw an exception
	connection.setSecureRandom(customRandom);
}

@Test
public void testSetSecureRandomWithNull() {
	try {
	connection.setSecureRandom(null);
	fail("Should throw IllegalArgumentException with null SecureRandom");
	} catch (IllegalArgumentException e) {
	// Expected behavior - test passes
	}
}

@Test
public void testGetConnectionInfoThrowsWhenNotConnected() {
	try {
		connection.getConnectionInfo();
		fail("Should throw IllegalStateException when not connected");
	} catch (IllegalStateException e) {
		assertTrue(e.getMessage().contains("establish a connection first"), "Exception message should indicate connection required");
	} catch (Exception e) {
		fail("Should throw IllegalStateException, got: " + e.getClass().getSimpleName());
	}
}

@Test
public void testGetLocalSocketAddressThrowsWhenNotConnected() {
	try {
		connection.getLocalSocketAddress();
		fail("Should throw IllegalStateException when not connected");
	} catch (IllegalStateException e) {
		assertTrue(e.getMessage().contains("establish a connection first"), "Exception message should indicate connection required");
	} catch (Exception e) {
		fail("Should throw IllegalStateException, got: " + e.getClass().getSimpleName());
	}
}

@Test
public void testGetRemoteSocketAddressThrowsWhenNotConnected() {
	try {
		connection.getRemoteSocketAddress();
		fail("Should throw IllegalStateException when not connected");
	} catch (IllegalStateException e) {
		assertTrue(e.getMessage().contains("establish a connection first"), "Exception message should indicate connection required");
	} catch (Exception e) {
		fail("Should throw IllegalStateException, got: " + e.getClass().getSimpleName());
	}
}

@Test
public void testIsAuthMethodAvailableWithNullMethod() {
	try {
	connection.isAuthMethodAvailable("testuser", null);
	fail("Should throw IllegalArgumentException with null method");
	} catch (IllegalArgumentException e) {
	assertTrue(e.getMessage().contains("method argument"), "Exception message should mention method argument");
	} catch (Exception e) {
	fail("Should throw IllegalArgumentException, got: " +
		e.getClass().getSimpleName());
	}
}

@Test
public void testSendIgnorePacketWithNullData() {
	try {
	connection.sendIgnorePacket(null);
	fail("Should throw IllegalArgumentException with null data");
	} catch (IllegalArgumentException e) {
	assertTrue(e.getMessage().contains("data argument"), "Exception message should mention data argument");
	} catch (Exception e) {
	// May also throw IllegalStateException if not connected
	assertTrue(e instanceof IllegalArgumentException || e instanceof
													IllegalStateException, "Should throw IllegalArgumentException or IllegalStateException");
	}
}

@Test
public void testSendIgnorePacketWithEmptyData() {
	try {
	connection.sendIgnorePacket(new byte[0]);
	fail("Should throw some exception when not connected");
	} catch (IllegalStateException e) {
	// Expected when not connected
	} catch (Exception e) {
	// Some other exception is also acceptable since we're not connected
	}
}

@Test
public void testCloseWithoutConnection() {
	// Should not throw an exception even if not connected
	connection.close();
}

@Test
public void testSetCompressionWithoutConnection() {
	// Should succeed when not connected (sets internal flag)
	try {
	connection.setCompression(true);
	} catch (IOException e) {
	fail("Should not throw IOException when not connected: " +
		e.getMessage());
	}
}

@Test
public void testConnectionIdentification() {
	String identification = Connection.identification;

	assertNotNull(identification, "Identification should not be null");
	assertTrue(identification.length() > 0, "Identification should not be empty");
	assertTrue(identification.contains("TrileadSSH2Java"), "Identification should contain version info");
}

@Test
public void testHostnameNullHandling() {
	// Test with null hostname (may be allowed by implementation)
	try {
	Connection conn = new Connection(null, 22);
	assertNull(conn.getHostname(), "Null hostname should be preserved");
	} catch (Exception e) {
	// If constructor throws exception with null hostname, that's also
	// acceptable
	}
}

@Test
public void testPortEdgeCases() {
	// Test with port 0
	Connection conn1 = new Connection("example.com", 0);
	assertEquals(0, conn1.getPort(), "Port 0 should be preserved");

	// Test with high port number
	Connection conn2 = new Connection("example.com", 65535);
	assertEquals(65535, conn2.getPort(), "High port should be preserved");

	// Test with negative port (behavior depends on implementation)
	Connection conn3 = new Connection("example.com", -1);
	assertEquals(-1, conn3.getPort(), "Negative port should be preserved");
}

@Test
public void testSetCipherAndMACMethods() {
	// Use valid cipher and MAC names from the available lists
	String[] availableCiphers = Connection.getAvailableCiphers();
	String[] availableMACs = Connection.getAvailableMACs();

	// Take first 2 ciphers and MACs for testing
	String[] testCiphers = {availableCiphers[0], availableCiphers.length > 1
													? availableCiphers[1]
													: availableCiphers[0]};
	String[] testMACs = {availableMACs[0], availableMACs.length > 1
											? availableMACs[1]
											: availableMACs[0]};

	// These should not throw exceptions
	connection.setClient2ServerCiphers(testCiphers);
	connection.setServer2ClientCiphers(testCiphers);
	connection.setClient2ServerMACs(testMACs);
	connection.setServer2ClientMACs(testMACs);
}

@Test
public void testSetAlgorithmMethods() {
	// Use valid algorithm names from available lists
	String[] availableAlgos = Connection.getAvailableServerHostKeyAlgorithms();
	String[] testAlgos = {availableAlgos[0], availableAlgos.length > 1
												? availableAlgos[1]
												: availableAlgos[0]};

	// These should not throw exceptions
	connection.setServerHostKeyAlgorithms(testAlgos);

	// For KEX algorithms, we'll test with a known algorithm
	String[] testKexAlgos = {"diffie-hellman-group1-sha1"}; // Basic DH group
	connection.setKeyExchangeAlgorithms(testKexAlgos);
}

@Test
public void testGetBannersReturnsEmptyBeforeAuthentication() {
	// Before any authentication attempt, AuthenticationManager has not been created
	// yet, so the accessor must return an empty list rather than throwing or
	// returning null.
	assertNotNull(connection.getBanners(), "getBanners() must never return null");
	assertTrue(connection.getBanners().isEmpty(),
			"getBanners() must be empty before authentication");
}
}
