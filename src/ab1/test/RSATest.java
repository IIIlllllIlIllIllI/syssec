package ab1.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import ab1.RSA;
import ab1.RSA.PrivateKey;
import ab1.RSA.PublicKey;
import ab1.impl.Nachnamen.RSAImpl;

public class RSATest {
	RSA rsa = new RSAImpl();

	private static int KEYLENGTH = 1024;
	private static int TESTCOUNT_LONG = 100;
	private static int TESTCOUNT_SHORT = 1000;
	
	private static int TESTCOUNT_SIGN = 1000;

	@Before
	public void initialize() {
		rsa.init(KEYLENGTH);
	}

	// 1 Pts
	@Test
	public void testInit() {

		PublicKey pub = rsa.getPublicKey();
		PrivateKey priv = rsa.getPrivateKey();

		assertEquals(KEYLENGTH, pub.getN().bitLength());
		assertEquals(KEYLENGTH, priv.getN().bitLength());
	}

	// 1 Pts
	@Test
	public void testEncryptionShort() {

		Random r = new Random(System.currentTimeMillis());
		int dataLength = 4;
		byte[] data = new byte[dataLength];

		for (int i = 0; i < TESTCOUNT_SHORT; i++) {
			r.nextBytes(data);

			if (r.nextBoolean()) {
				//Keine Änderung des Schlüsseltexts
				byte[] cipher = rsa.encrypt(data, false);

				byte[] message_decrypted = rsa.decrypt(cipher);

				assertArrayEquals(data, message_decrypted);
			} else {
				byte[] cipher = rsa.encrypt(data, false);

				// Baue Fehler ab der Hälfte der Daten ein (davor stehen eventuell
				// Protokolldaten)
				for (int j = dataLength / 2; j < dataLength; j++)
					cipher[j] = (byte) (cipher[j] ^ 0xFF);

				byte[] message_decrypted = rsa.decrypt(cipher);

				assertEquals(false, Arrays.equals(data, message_decrypted));
			}
		}
	}

	// 2 Pts
	@Test
	public void testEncryptionLong() {

		Random r = new Random(System.currentTimeMillis());
		int dataLength = KEYLENGTH / 8 * 200; // 200-fache Schlüssellänge
		byte[] data = new byte[dataLength];

		for (int i = 0; i < TESTCOUNT_LONG; i++) {
			r.nextBytes(data);

			if (r.nextBoolean()) {
				//Keine Änderung des Schlüsseltexts
				byte[] cipher = rsa.encrypt(data, false);

				byte[] message_decrypted = rsa.decrypt(cipher);

				assertArrayEquals(data, message_decrypted);
			} else {
				byte[] cipher = rsa.encrypt(data, false);

				// Baue Fehler ab der Hälfte der Daten ein (davor stehen eventuell Protokolldaten)
				for (int j = dataLength / 2; j < dataLength; j++)
					cipher[j] = (byte) (cipher[j] ^ 0xFF);

				byte[] message_decrypted = rsa.decrypt(cipher);

				assertEquals(false, Arrays.equals(data, message_decrypted));
			}
		}
	}

	// 1 Pts
	@Test
	public void testEncryptionShort_OAEP() {

		// Folgt
	}

	// 2 Pts
	@Test
	public void testEncryptionLong_OAEP() {

		// Folgt
	}

	// 3 Pts
	@Test
	public void testSignature() {

		Random r = new Random(System.currentTimeMillis());
		int dataLength = KEYLENGTH / 8 * 200;
		byte[] data = new byte[dataLength];

		for (int i = 0; i < TESTCOUNT_SIGN; i++) {
			r.nextBytes(data);

			if (r.nextBoolean()) {
				//Keine Änderung der Signatur/Daten
				byte[] sign = rsa.sign(data);
				
				assertEquals(true, sign.length <= KEYLENGTH/8);	//Signatur darf maximal so lang wie der Schlüssel sein (einfache Abfrage, ob wohl gehasht wurde)

				assertEquals(true, rsa.verify(data, sign));
			} else {
				byte[] sign = rsa.sign(data);

				// Baue einen einzigen Bit-Fehler in die Daten ein
				int pos = r.nextInt(data.length);
				data[pos] = (byte)(data[pos]^0x01);
				
				assertEquals(true, sign.length <= KEYLENGTH/8);	//Signatur darf maximal so lang wie der Schlüssel sein (einfache Abfrage, ob wohl gehasht wurde)

				assertEquals(false, rsa.verify(data, sign));
			}
		}
	}
}
