package ab1.impl.Nachnamen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private int bitlength;

	@Override
	public void init(int n) {
		bitlength = n;
		BigInteger p = null, q = null;
		BigInteger nn;
		SecureRandom rand = new SecureRandom();
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
		// phi(n)=(p-1)(q-1)
		BigInteger phi = q.subtract(BigInteger.ONE).multiply(p.subtract(BigInteger.ONE));
		// e= 2^16+1
		BigInteger e = new BigInteger("65537");
		// e=e.pow(16).add(BigInteger.ONE);
		while (!e.gcd(phi).equals(BigInteger.ONE) || e.equals(BigInteger.ONE) || e.equals(BigInteger.ZERO)) {
			e = e.add(new BigInteger("2"));
		}
		BigInteger d = e.modInverse(phi);
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
		byte[] result=toByteArray((toBigInt(data).modPow(publicKey.getE(), publicKey.getN())));
		System.out.println(Arrays.toString(data));
		System.out.println(Arrays.toString(result));
		return result;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		byte[] result=toByteArray((toBigInt(data).modPow(privateKey.getD(), privateKey.getN())));
		System.out.println(Arrays.toString(data));
		System.out.println(Arrays.toString(result));		
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
		return new BigInteger(1,arr);
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


}
