package com.trilead.ssh2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.trilead.ssh2.channel.Channel;
import com.trilead.ssh2.channel.ChannelInputStream;
import com.trilead.ssh2.channel.ChannelManager;
import com.trilead.ssh2.channel.ChannelOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.Mock;

@ExtendWith(MockitoExtension.class)
public class SessionTest {

@Mock private ChannelManager mockChannelManager;

@Mock private Channel mockChannel;

private SecureRandom secureRandom;
private Session session;

@BeforeEach
public void setUp() throws IOException {
	secureRandom = new SecureRandom();

	// Setup mock behavior
	when(mockChannelManager.openSessionChannel(Channel.CHANNEL_BUFFER_SIZE)).thenReturn(mockChannel);

	session = new Session(mockChannelManager, secureRandom, Channel.CHANNEL_BUFFER_SIZE);
}

@Test
public void testSessionConstruction() throws IOException {
	// Verify that session was created with channel manager
	verify(mockChannelManager).openSessionChannel(Channel.CHANNEL_BUFFER_SIZE);
	assertNotNull(session, "Session should be created successfully");
}

@Test
public void testRequestDumbPTY() throws IOException {
	// Should not throw an exception
	session.requestDumbPTY();

	// This calls requestPTY with default parameters, so we can't verify
	// much more without mocking the channel communication
}

@Test
public void testRequestPTYWithTermOnly() throws IOException {
	String termType = "vt100";

	// Should not throw an exception
	session.requestPTY(termType);

	// Verify the method completes without error
}

@Test
public void testRequestPTYWithFullParameters() throws IOException {
	String termType = "xterm-256color";
	int width = 80;
	int height = 24;
	int pixelWidth = 640;
	int pixelHeight = 480;
	byte[] termModes = {1, 0, 0, 0, 0}; // Some dummy terminal modes

	// Should not throw an exception
	session.requestPTY(termType, width, height, pixelWidth, pixelHeight,
					termModes);
}

@Test
public void testRequestPTYWithNullTerminalModes() throws IOException {
	session.requestPTY("xterm", 80, 24, 640, 480, null);
}

@Test
public void testRequestPTYWithZeroDimensions() throws IOException {
	session.requestPTY("xterm", 0, 0, 0, 0, null);
}

@Test
public void testResizePTY() throws IOException {
	session.resizePTY(100, 30, 800, 600);

	// Method should complete without error
}

@Test
public void testResizePTYWithZeroDimensions() throws IOException {
	session.resizePTY(0, 0, 0, 0);
}

@Test
public void testRequestX11Forwarding() throws IOException {
	String hostname = "localhost";
	int port = 6000;
	byte[] cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	boolean singleConnection = false;

	session.requestX11Forwarding(hostname, port, cookie, singleConnection);
}

@Test
public void testRequestX11ForwardingWithNullHostname() {
	assertThrows(IllegalArgumentException.class, () -> {
		byte[] cookie = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
		session.requestX11Forwarding(null, 6000, cookie, false);
	});
}

@Test
public void testRequestX11ForwardingWithNullCookie() throws IOException {
	session.requestX11Forwarding("localhost", 6000, null, true);
}

@Test
public void testExecCommand() throws IOException {
	String command = "ls -la";

	session.execCommand(command);
}

@Test
public void testExecCommandWithNull() {
	assertThrows(IllegalArgumentException.class, () ->
		session.execCommand(null));
}

@Test
public void testExecCommandWithEmptyString() throws IOException {
	session.execCommand("");
}

@Test
public void testStartShell() throws IOException {
	session.startShell();
}

@Test
public void testStartSubSystem() throws IOException {
	session.startSubSystem("sftp");
}

@Test
public void testStartSubSystemWithNull() {
	assertThrows(IllegalArgumentException.class, () ->
		session.startSubSystem(null));
}

@Test
public void testStartSubSystemWithEmptyString() throws IOException {
	session.startSubSystem("");
}

@Test
public void testPing() throws IOException {
	session.ping();
}

@Test
public void testGetExitStatusWhenNull() {
	when(mockChannel.getExitStatus()).thenReturn(null);

	Integer exitStatus = session.getExitStatus();

	assertNull(exitStatus, "Exit status should be null when not available");
	verify(mockChannel).getExitStatus();
}

@Test
public void testGetExitStatusWhenAvailable() {
	Integer expectedExitCode = 0;
	when(mockChannel.getExitStatus()).thenReturn(expectedExitCode);

	Integer exitStatus = session.getExitStatus();

	assertEquals(expectedExitCode, exitStatus, "Exit status should match channel exit status");
	verify(mockChannel).getExitStatus();
}

@Test
public void testGetExitStatusWithNonZeroCode() {
	Integer expectedExitCode = 1;
	when(mockChannel.getExitStatus()).thenReturn(expectedExitCode);

	Integer exitStatus = session.getExitStatus();

	assertEquals(expectedExitCode, exitStatus, "Exit status should match channel exit status");
}

@Test
public void testGetExitSignalWhenNull() {
	when(mockChannel.getExitSignal()).thenReturn(null);

	String signal = session.getExitSignal();

	assertNull(signal, "Exit signal should be null when not available");
	verify(mockChannel).getExitSignal();
}

@Test
public void testGetExitSignalWhenAvailable() {
	String expectedSignal = "SIGTERM";
	when(mockChannel.getExitSignal()).thenReturn(expectedSignal);

	String signal = session.getExitSignal();

	assertEquals(expectedSignal,
				signal, "Exit signal should match channel exit signal");
	verify(mockChannel).getExitSignal();
}

@Test
public void testGetStreams() {
	ChannelInputStream mockStdout = mock(ChannelInputStream.class);
	ChannelInputStream mockStderr = mock(ChannelInputStream.class);
	ChannelOutputStream mockStdin = mock(ChannelOutputStream.class);

	when(mockChannel.getStdoutStream()).thenReturn(mockStdout);
	when(mockChannel.getStderrStream()).thenReturn(mockStderr);
	when(mockChannel.getStdinStream()).thenReturn(mockStdin);

	InputStream stdout = session.getStdout();
	InputStream stderr = session.getStderr();
	OutputStream stdin = session.getStdin();

	assertSame(mockStdout, stdout, "Stdout should be from channel");
	assertSame(mockStderr, stderr, "Stderr should be from channel");
	assertSame(mockStdin, stdin, "Stdin should be from channel");

	verify(mockChannel).getStdoutStream();
	verify(mockChannel).getStderrStream();
	verify(mockChannel).getStdinStream();
}

@Test
@SuppressWarnings("deprecation")
public void testWaitUntilDataAvailable() {
	int conditions = ChannelCondition.STDOUT_DATA;
	when(mockChannelManager.waitForCondition(eq(mockChannel), eq(1000L),
											anyInt()))
		.thenReturn(conditions);

	int result = session.waitUntilDataAvailable(1000L);

	assertEquals(1, result, "Should return 1 for data available");
	verify(mockChannelManager)
		.waitForCondition(eq(mockChannel), eq(1000L), anyInt());
}

@Test
@SuppressWarnings("deprecation")
public void testWaitUntilDataAvailableWithZeroTimeout() {
	when(mockChannelManager.waitForCondition(eq(mockChannel), eq(0L), anyInt()))
		.thenReturn(ChannelCondition.EOF);

	int result = session.waitUntilDataAvailable(0L);

	assertEquals(0, result, "Should return 0 for EOF");
	verify(mockChannelManager)
		.waitForCondition(eq(mockChannel), eq(0L), anyInt());
}

@Test
public void testWaitForCondition() {
	int condition = ChannelCondition.CLOSED;
	long timeout = 5000L;
	int expectedResult = ChannelCondition.CLOSED;

	when(mockChannelManager.waitForCondition(mockChannel, timeout, condition))
		.thenReturn(expectedResult);

	int result = session.waitForCondition(condition, timeout);

	assertEquals(expectedResult,
				result, "Should return channel manager result");
	verify(mockChannelManager)
		.waitForCondition(mockChannel, timeout, condition);
}

@Test
public void testWaitForConditionMultipleBits() {
	int condition = ChannelCondition.STDOUT_DATA | ChannelCondition.STDERR_DATA;

	when(mockChannelManager.waitForCondition(mockChannel, 2000L, condition))
		.thenReturn(condition);

	int result = session.waitForCondition(condition, 2000L);

	assertEquals(condition, result, "Should return the conditions");
	verify(mockChannelManager).waitForCondition(mockChannel, 2000L, condition);
}

@Test
public void testClose() throws IOException {
	session.close();

	verify(mockChannelManager)
		.closeChannel(eq(mockChannel), anyString(), eq(true));
}

@Test
public void testCloseIdempotent() throws IOException {
	session.close();
	session.close(); // Second close should be safe

	// Should only call closeChannel once due to flag_closed
	verify(mockChannelManager, times(1))
		.closeChannel(eq(mockChannel), anyString(), eq(true));
}

@Test
public void testSessionConstructionFailsWithNullChannelManager() {
	assertThrows(NullPointerException.class, () ->
		new Session(null, secureRandom, Channel.CHANNEL_BUFFER_SIZE));
}

@Test
public void testSessionConstructionWithNullSecureRandom() throws IOException {
	when(mockChannelManager.openSessionChannel(Channel.CHANNEL_BUFFER_SIZE)).thenReturn(mockChannel);

	// Constructor should accept null SecureRandom without throwing
	new Session(mockChannelManager, null, Channel.CHANNEL_BUFFER_SIZE);
}

@Test
public void testSessionConstructionWithIOException() throws IOException {
	ChannelManager failingChannelManager = mock(ChannelManager.class);
	when(failingChannelManager.openSessionChannel(Channel.CHANNEL_BUFFER_SIZE))
		.thenThrow(new IOException("Mock failure"));

	try {
	new Session(failingChannelManager, secureRandom, Channel.CHANNEL_BUFFER_SIZE);
	fail("Should propagate IOException from channel manager");
	} catch (IOException e) {
	assertEquals(e.getMessage(), "Mock failure");
	}
}
}
