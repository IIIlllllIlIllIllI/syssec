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
		BigInteger p, a, g, pPrime;
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
			a = (new BigInteger(pPrime.subtract(ONE).bitLength() + 100, rand)).mod(pPrime.subtract(ONE));
		} while (a.equals(ZERO));
		BigInteger h = g.modPow(a, p);
		privateKey = new PrivateKey(p, g, a);
		publicKey = new PublicKey(p, g, h);

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
		int keylength=privateKey.getP().bitLength();
		int blocklength=keylength/8-1;
		SecureRandom rand = new SecureRandom();
		BigInteger pPrime = privateKey.getP().subtract(BigInteger.ONE).divide(TWO);
		BigInteger r,c1,s;
		do {
			r = (new BigInteger(pPrime.bitLength() + 100, rand)).mod(pPrime);
		} while (r.equals(ZERO));
		
		
		c1=pow(privateKey.getG(),r);
		s=pow(publicKey.getE(),r);
		
		
		ArrayList<Byte> al = new ArrayList<>();
		byte[] rarr=toByteArray(r);
		al.add((byte) rarr.length);
		for (int i = 0; i < rarr.length; i++) {
			al.add(rarr[i]);
		}
		byte[] result;

        // dividing the data into 'blocklength' byte blocks and encrypt them
		for (int i = 0; i < data.length; i += blocklength) {
			byte[] tmp = new byte[blocklength+1];
			int lenLastBlock = data.length - i;

			//check if the last block is shorter than 127 bytes
			if (blocklength < lenLastBlock) {
				lenLastBlock = blocklength;
			}

			System.arraycopy(data, i, tmp, tmp.length - lenLastBlock, lenLastBlock);
			//write padding information into first byte
			tmp[0] = (byte) (tmp.length - lenLastBlock);


			// encrypt the current block with c = m^e MOD n
			tmp = toByteArray((toBigInt(tmp).multiply(s)));

			// if the encrypted block is too short, add a padding to fill up to 128 bytes
			if (tmp.length % (blocklength+1) != 0) {
				for (int j = 0; j < blocklength+1 - tmp.length % (blocklength+1); j++) {
					al.add((byte) 0);
				}
			}
			//copy
			for (int j = 0; j < tmp.length; j++) {
				al.add(tmp[j]);
			}
		}
		//copy to byte array
		result = new byte[al.size()];
		for (int i = 0; i < al.size(); i++) {
			result[i] = al.get(i);
		}

		return result;

	}

	@Override
	public byte[] decrypt(byte[] data) {
		// TODO Auto-generated method stub
		return null;
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
		    if (exponent.testBit(0)) result = result.multiply(base);
		    base = base.multiply(base);
		    exponent = exponent.shiftRight(1);
		  }
		  return result;
		}

}