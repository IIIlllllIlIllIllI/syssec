package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import ab2.ElGamal;

public class ElGamalImpl implements ElGamal {
	private PublicKey publicKey;
	private PrivateKey privateKey;
	static final BigInteger ONE = BigInteger.ONE;
	static final BigInteger TWO = ONE.add(ONE);
	static final BigInteger ZERO = BigInteger.ZERO;

	@Override
	public void init(int n) {
		SecureRandom rand = new SecureRandom();
		BigInteger p, d, g, pPrime;
		do {
			p = BigInteger.probablePrime(n - 1, rand);
			p = TWO.multiply(p).add(ONE);
		} while (!p.isProbablePrime(40) || p.bitLength() != n);
		g = (new BigInteger(p.bitLength() + 100, rand)).mod(p);

		pPrime = p.subtract(ONE).divide(TWO);

		while (!g.modPow(pPrime, p).equals(ONE)) {
			if (g.modPow(pPrime.multiply(TWO), p).equals(ONE))
				g = g.modPow(TWO, p);
			else
				g = (new BigInteger(p.bitLength() + 100, rand)).mod(p);
		}
		do {
			d = (new BigInteger(pPrime.subtract(ONE).bitLength() + 100, rand)).mod(pPrime.subtract(ONE));
		} while (d.equals(ZERO));
		BigInteger e = g.modPow(d, p);
		privateKey = new PrivateKey(p, g, d);
		publicKey = new PublicKey(p, g, e);

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
	public byte[] encrypt(byte[] data) {
		int keylength = publicKey.getP().bitLength();
		int blocklength = keylength / 8 - 1;
		int optimalCipherBlockLength = keylength / 8 * 2;
		SecureRandom rand = new SecureRandom();
		BigInteger r, s, c1, pPrime;
		pPrime = publicKey.getP().subtract(BigInteger.ONE).divide(TWO);

		do {
			r = (new BigInteger(pPrime.bitLength() + 100, rand)).mod(pPrime);
			System.out.println("*");
		} while (r.equals(ZERO) || r.gcd(publicKey.getP()) != ONE);

		c1 = publicKey.getG().modPow(r, publicKey.getP());
		s = publicKey.getE().modPow(r, publicKey.getP());

		ArrayList<Byte> arrayList = new ArrayList<>();
		byte[] c1Bytes = toByteArray(c1);
		arrayList.add((byte) c1Bytes.length);
		for (int i = 0; i < c1Bytes.length; i++) {
			arrayList.add(c1Bytes[i]);
		}

		// dividing the data into 'blocklength' byte blocks and encrypt them
		for (int i = 0; i < data.length; i += blocklength) {
			byte[] m_i = new byte[blocklength + 1];
			int lenLastBlock = data.length - i;

			// check if the last block is shorter than 127 bytes
			if (blocklength < lenLastBlock) {
				lenLastBlock = blocklength;
			}

			System.arraycopy(data, i, m_i, m_i.length - lenLastBlock, lenLastBlock);
			// write padding information into first byte
			m_i[0] = (byte) (m_i.length - lenLastBlock);

			byte[] tmp = new byte[optimalCipherBlockLength];
			System.arraycopy(m_i, 0, tmp, 0, m_i.length);
			// if the block is too short, add a padding to fill up to
			// 'optimalCipherBlockLength'
			for (int j = m_i.length; j < optimalCipherBlockLength; j++) {
				m_i[j] = 0;
			}

			// encrypt the current block
			// c2
			m_i = toByteArray((toBigInt(m_i).multiply(s)));

			// copy
			for (int j = 0; j < m_i.length; j++) {
				arrayList.add(m_i[j]);
			}

		}
		// copy to byte array
		byte[] result = new byte[arrayList.size()];
		for (int i = 0; i < arrayList.size(); i++) {
			result[i] = arrayList.get(i);
		}
		return result;

	}

	@Override
	public byte[] decrypt(byte[] data) {
		int keylength = privateKey.getP().bitLength();
		int optimalCipherBlockLength = keylength / 8 * 2;
		byte c1len = data[0];
		byte[] c1arr = new byte[c1len];
		for (int i = 1; i <= c1len; i++) {
			c1arr[i] = data[i];
		}
		BigInteger c1 = toBigInt(c1arr);
		BigInteger s = c1.modPow(privateKey.getD(), privateKey.getP());
		// only accept full blocks as received from encrypt-method
		if (data.length - c1len - 1 % optimalCipherBlockLength != 0) {
			System.err.println("input too short");
			return data;
		}

		ArrayList<Byte> al = new ArrayList<>();

		// divide the cyphertext into blocks and decrypt them
		for (int i = 0; i < data.length; i += optimalCipherBlockLength) {
			byte[] c2_i = new byte[optimalCipherBlockLength];

			System.arraycopy(data, i, c2_i, 0, c2_i.length);

			// decrypt the block
			//m_i
			c2_i = toByteArray((toBigInt(c2_i).multiply(s.modInverse(privateKey.getP()).mod(privateKey.getP()))));

			// get padding information
			int paddingLength = Math.abs(c2_i[0]);

			// ignore padded bytes
			for (int j = paddingLength; j < c2_i.length; j++) {

				al.add(c2_i[j]);
			}
		}
		// copy to byte array
		byte[] result = new byte[al.size()];
		for (int i = 0; i < al.size(); i++) {
			result[i] = al.get(i);
		}
		return result;

	}

	@Override
	public byte[] sign(byte[] message) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		// TODO Auto-generated method stub
		return null;
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

	BigInteger pow(BigInteger base, BigInteger exponent) {
		BigInteger result = BigInteger.ONE;
		while (exponent.signum() > 0) {
			if (exponent.testBit(0))
				result = result.multiply(base);
			base = base.multiply(base);
			exponent = exponent.shiftRight(1);
		}
		return result;
	}

}