package ab1.impl.Nachnamen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	public static void main(String[] args) {
		RSAImpl abc = new RSAImpl();
		abc.init(6);
		byte[] b=new byte[1024];
		Random random=new Random();
			random.nextBytes(b);
		abc.encrypt(b, false);
	}

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private int bitlength;

	@Override
	public void init(int n) {
		bitlength=n;
		BigInteger p = null, q = null;
		SecureRandom rand = new SecureRandom();
		do {
			p = BigInteger.probablePrime(n/2, rand);
		} while (p.equals(BigInteger.ONE) || p.equals(new BigInteger("2")));
		do {
			rand.setSeed((long) Math.random() * 100);
			q = BigInteger.probablePrime(n/2, rand);
		} while (q.equals(p) || q.equals(BigInteger.ONE) || q.equals(new BigInteger("2")));
		System.out.println("" + q + "\n" + p);
		// n = p*q
		BigInteger nn = p.multiply(q);
		// phi(n)=(p-1)(q-1)
		BigInteger phi = q.subtract(BigInteger.ONE).multiply(p.subtract(BigInteger.ONE));
		System.out.println("" + phi);
		// e= 2^16+1
		BigInteger e = new BigInteger("65537");
		// e=e.pow(16).add(BigInteger.ONE);
		while (!e.gcd(phi).equals(BigInteger.ONE) || e.equals(BigInteger.ONE) || e.equals(BigInteger.ZERO)) {
			e = e.add(new BigInteger("2"));
		}
		System.out.println("" + e);
		BigInteger d = e.modInverse(phi);
		System.out.println(d);
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
		byte[] result=new byte[data.length];
		if(!activateOAEP){
			for (int i = 0; i < data.length/bitlength; i++) {
				byte[] block=Arrays.copyOfRange(data, i*bitlength, i*bitlength+bitlength-1);
				System.out.println(Arrays.toString(block));
				System.out.println(new BigInteger(Arrays.toString(block)));
				block=(new BigInteger(Arrays.toString(block))).pow(publicKey.getE().intValue()).mod(publicKey.getN()).toByteArray();
				

			}
			
		}
		return null;
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

}
