package ab1.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import ab1.RSA;

public class RSAImpl implements RSA {
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private static final String HASH_FUNCTION = "SHA-256";

	@Override
	public void init(int n) {

		// initializing the BigIntegers for the prime numbers p and q and the product n = p * q
		BigInteger p = null, q = null;
		BigInteger nn;
		SecureRandom rand = new SecureRandom();

		// generating the prime numbers p and q so long as n does not have the correct bitLength
		do {
			do {
				p = BigInteger.probablePrime(n / 2, rand);
			} while (p.equals(BigInteger.ONE) || p.equals(new BigInteger("2")));
			do {
				q = BigInteger.probablePrime(n / 2, rand);
			} while (q.equals(p) || q.equals(BigInteger.ONE) || q.equals(new BigInteger("2")));
			// n = p*q
			nn = p.multiply(q);
		} while (nn.bitLength() != n);

		// phi(n) = (p-1) * (q-1)
		BigInteger phi = q.subtract(BigInteger.ONE).multiply(p.subtract(BigInteger.ONE));

		// initializing e for the encryption with e = 2^16 + 1
		BigInteger e = new BigInteger("65537");

		// initializing d for the decryption with d == e^-1 MOD phi(n)
		BigInteger d = e.modInverse(phi);

		// setting public and private keys
		publicKey = new PublicKey(nn, e);
		privateKey = new PrivateKey(nn, d);

	}

	@Override
	public PublicKey getPublicKey() {
		return publicKey;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public byte[] encrypt(byte[] data, boolean activateOAEP) {

		ArrayList<Byte> al = new ArrayList<>();
		byte[] result;

        // dividing the data into 127 byte blocks and encrypt them
		for (int i = 0; i < data.length; i += 127) {
			byte[] tmp = new byte[128];
			int lenLastBlock = data.length - i;


			if (127 < lenLastBlock) {
				lenLastBlock = 127;
			}

			System.arraycopy(data, i, tmp, tmp.length - lenLastBlock, lenLastBlock);
			tmp[0] = (byte) (tmp.length - lenLastBlock);

			// using Optimal asymmetric encryption padding if activated
			if (activateOAEP) {
				SecureRandom secureRandom = new SecureRandom();
				byte[] b = new byte[tmp.length - lenLastBlock - 1];
				secureRandom.nextBytes(b);
				for (int a = 1; a < tmp.length - lenLastBlock; a++) {
					tmp[a] = b[a - 1];
				}
			}

			// encrypt the current block with c = m^e MOD n
			tmp = toByteArray((toBigInt(tmp).modPow(publicKey.getE(), publicKey.getN())));

			// if the encrypted block is too short, add a padding
			if (tmp.length % 128 != 0) {
				for (int j = 0; j < 128 - tmp.length % 128; j++) {
					al.add((byte) 0);
				}
			}
			for (int j = 0; j < tmp.length; j++) {
				al.add(tmp[j]);
			}
		}
		result = new byte[al.size()];

		for (int i = 0; i < al.size(); i++) {
			result[i] = al.get(i);
		}

		return result;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		if (data.length % 128 != 0) {
			System.err.println("input too short");
			return data;
		}

		ArrayList<Byte> al = new ArrayList<>();
		byte[] result;

		// divide the cyphertext into blocks and decrypt them
		for (int i = 0; i < data.length; i += 128) {
			byte[] tmp = new byte[128];

			System.arraycopy(data, i, tmp, 0, tmp.length);

			// decrypt the block with m = c^d MOD n
			tmp = toByteArray((toBigInt(tmp).modPow(privateKey.getD(), privateKey.getN())));

			int paddingLength = Math.abs(tmp[0]);

			for (int j = paddingLength; j < tmp.length; j++) {

				al.add(tmp[j]);
			}
		}
		result = new byte[al.size()];
		for (int i = 0; i < al.size(); i++) {
			result[i] = al.get(i);
		}
		return result;
	}

	@Override
	public byte[] sign(byte[] message) {

	    // hashing the message
		message = hash(message);

		// sign the hashed message with m^d MOD n
		byte[] signature = toByteArray((toBigInt(message).modPow(privateKey.getD(), privateKey.getN())));
		;
		return signature;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {

	    // verify the signature with c^e MOD n
		byte[] result = toByteArray((toBigInt(signature).modPow(publicKey.getE(), publicKey.getN())));

		// hashing the message
		message = hash(message);
		message = toByteArray(toBigInt(message));

		// check if the decrypted signature and the message are the same
		return Arrays.equals(message, result);
	}

	private static BigInteger toBigInt(byte[] arr) {
		return new BigInteger(1, arr);
	}

	private static byte[] toByteArray(BigInteger bi) {
		byte[] array = bi.toByteArray();
		if (array[0] == 0) {
			byte[] tmp = new byte[array.length - 1];
			System.arraycopy(array, 1, tmp, 0, tmp.length);
			array = tmp;
		}
		return array;
	}

	private byte[] hash(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_FUNCTION);

			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;

	}

}
