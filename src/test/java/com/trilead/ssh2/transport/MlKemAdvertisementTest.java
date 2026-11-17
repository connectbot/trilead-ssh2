package com.trilead.ssh2.transport;

import com.trilead.ssh2.crypto.dh.MlKemHybridExchange;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class MlKemAdvertisementTest {
	@Test
	void advertisesHybridWhenNativeKeyGeneratorExistsWithoutMlKemKem() throws Exception {
		Class<?> kem;
		try {
			kem = Class.forName("javax.crypto.KEM");
		} catch (ClassNotFoundException e) {
			assumeTrue(false, "Requires a runtime with javax.crypto.KEM");
			return;
		}
		Provider[] originalProviders = Security.getProviders();
		Provider provider = new Provider("PartialMlKemTest", "1.0", "Advertises only a key generator") {};
		provider.put("KeyPairGenerator.ML-KEM-768", UnusableGenerator.class.getName());
		String manager = KexManager.class.getName();
		URL classes = KexManager.class.getProtectionDomain().getCodeSource().getLocation();
		try (URLClassLoader loader = new URLClassLoader(new URL[] {classes}, KexManager.class.getClassLoader()) {
			@Override
			protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
				if (name.equals(manager)) {
					// Give KexManager a fresh static capability check with the test provider installed.
					return findClass(name);
				}
				return super.loadClass(name, resolve);
			}
		}) {
			// Newer JDK updates can backport ML-KEM. Mask that service for this fixture.
			for (Provider installed : originalProviders) {
				if (installed.getService("KEM", "ML-KEM") != null) {
					Security.removeProvider(installed.getName());
				}
			}
			Security.insertProviderAt(provider, 1);
			assertEquals(provider, KeyPairGenerator.getInstance("ML-KEM-768").getProvider());
			InvocationTargetException unavailable = assertThrows(InvocationTargetException.class,
					() -> kem.getMethod("getInstance", String.class).invoke(null, "ML-KEM"));
			assertInstanceOf(NoSuchAlgorithmException.class, unavailable.getCause());
			Class<?> freshManager = Class.forName(manager, true, loader);
			String[] offered = (String[]) freshManager.getMethod("getDefaultKexAlgorithmList").invoke(null);
			assertTrue(Arrays.asList(offered).contains(MlKemHybridExchange.NAME),
					"Bundled ML-KEM remains usable and should be advertised");
			MlKemHybridExchange exchange = new MlKemHybridExchange();
			exchange.init(MlKemHybridExchange.NAME);
			assertEquals(1216, exchange.getE().length);
		} finally {
			Security.removeProvider(provider.getName());
			for (int i = 0; i < originalProviders.length; i++) {
				Provider original = originalProviders[i];
				if (Security.getProvider(original.getName()) == null) {
					Security.insertProviderAt(original, i + 1);
				}
			}
		}
	}

	public static final class UnusableGenerator extends KeyPairGeneratorSpi {
		@Override
		public void initialize(int keysize, SecureRandom random) {
			throw new UnsupportedOperationException();
		}

		@Override
		public KeyPair generateKeyPair() {
			throw new UnsupportedOperationException();
		}
	}
}
