package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import static java.util.concurrent.TimeUnit.MINUTES;

import ab2.ElGamal;

public class ElGamalImpl implements ElGamal {
	private PublicKey publicKey;
	private PrivateKey privateKey;
	public static final BigInteger ONE = BigInteger.ONE;
	public static final BigInteger TWO = ONE.add(ONE);
	public static final BigInteger ZERO = BigInteger.ZERO;
	public static final int THREADS=8;
	private SecureRandom rand;
	private ExecutorService executorService;
	
	@Override
	public void init(int n) {
		rand=new SecureRandom();
		BigInteger p = null, d = null, g = null, pPrime;
		executorService=Executors.newFixedThreadPool(THREADS);
		List<Callable<BigInteger>> l = new ArrayList<>();
		for (int i = 0; i < THREADS; i++) {
			l.add(new PCallable(n,rand));
		}
		try {
			p=executorService.invokeAny(l, 5, MINUTES);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (ExecutionException e1) {
			e1.printStackTrace();
		} catch (TimeoutException e1) {
			e1.printStackTrace();
		}
		pPrime = p.subtract(ONE).divide(TWO);
		l = new ArrayList<>();
		for (int i = 0; i < THREADS; i++) {
			l.add(new GCallable(p,pPrime,rand));
		}
		try {
			g=executorService.invokeAny(l, 5, MINUTES);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (ExecutionException e1) {
			e1.printStackTrace();
		} catch (TimeoutException e1) {
			e1.printStackTrace();
		}
		l = new ArrayList<>();
		for (int i = 0; i < THREADS; i++) {
			l.add(new DCallable(pPrime,rand));
		}
		try {
			d=executorService.invokeAny(l, 5, MINUTES);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (ExecutionException e1) {
			e1.printStackTrace();
		} catch (TimeoutException e1) {
			e1.printStackTrace();
		}
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
		BigInteger r = null, s, c1, pPrime;
		pPrime = publicKey.getP().subtract(BigInteger.ONE).divide(TWO);
		

		ArrayList<Byte> arrayList = new ArrayList<>();


		// dividing the data into 'blocklength' byte blocks and encrypt them
		for (int i = 0; i < data.length; i += blocklength) {
			ArrayList<Callable<BigInteger>> l = new ArrayList<>();
			for (int j = 0; j < THREADS; j++) {
				l.add(new RCallable(publicKey.getP(), pPrime,rand));
			}
			try {
				r=executorService.invokeAny(l, 5, MINUTES);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			} catch (ExecutionException e1) {
				e1.printStackTrace();
			} catch (TimeoutException e1) {
				e1.printStackTrace();
			}

			c1 = publicKey.getG().modPow(r, publicKey.getP());
			s = publicKey.getE().modPow(r, publicKey.getP());
			
			byte[] c1Bytes = toByteArray(c1);
			for (int j = 0; j < optimalCipherBlockLength/2-c1Bytes.length; j++) {
				arrayList.add((byte) 0);
			}
			for (int j = 0; j < c1Bytes.length; j++) {
				arrayList.add(c1Bytes[j]);
			}
			byte[] m_i = new byte[blocklength + 1];
			int lenLastBlock = data.length - i;

			// check if the last block is shorter than 127 bytes
			if (blocklength < lenLastBlock) {
				lenLastBlock = blocklength;
			}
			m_i[0]=(byte) (blocklength-lenLastBlock+1);

			System.arraycopy(data, i, m_i, m_i.length - lenLastBlock, lenLastBlock);
			m_i=toByteArray(toBigInt(m_i).multiply(s).mod(publicKey.getP()));
			

			// encrypt the current block
			// c2
			for (int j = 0; j < optimalCipherBlockLength/2-m_i.length; j++) {
				arrayList.add((byte) 0);
			}

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
		// only accept full blocks as received from encrypt-method
		if (data.length % optimalCipherBlockLength != 0) {
			System.err.println("input has not optimalCipherBlockLength");
			return data;
		}



		ArrayList<Byte> al = new ArrayList<>();

		// divide the cyphertext into blocks and decrypt them
		for (int i = 0; i < data.length; i += optimalCipherBlockLength) {
			byte[] c1_i = new byte[optimalCipherBlockLength/2];
			System.arraycopy(data, i, c1_i, 0, c1_i.length);
			BigInteger c1 = toBigInt(c1_i);
			BigInteger s = c1.modPow(privateKey.getD(), privateKey.getP());
			byte[] c2_i = new byte[optimalCipherBlockLength/2];

			System.arraycopy(data, i+optimalCipherBlockLength/2, c2_i, 0, c2_i.length);

			// decrypt the block
			//m_i
			c2_i = toByteArray(toBigInt(c2_i).multiply(s.modInverse(privateKey.getP())).mod(privateKey.getP()));


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