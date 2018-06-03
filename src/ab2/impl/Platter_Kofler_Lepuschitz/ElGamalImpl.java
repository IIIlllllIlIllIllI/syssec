package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
	//algorithm used as hash-function
	private static final String HASH_FUNCTION = "SHA-256";
	
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
		int keylength = privateKey.getP().bitLength();
		BigInteger k = null, r;
		ArrayList<Callable<BigInteger>> l = new ArrayList<>();
		for (int i = 0; i < THREADS; i++) {
			l.add(new KCallable(privateKey.getP(),rand));
		}
		try {
			k=executorService.invokeAny(l, 5, MINUTES);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (ExecutionException e1) {
			e1.printStackTrace();
		} catch (TimeoutException e1) {
			e1.printStackTrace();
		}
		r=privateKey.getG().modPow(k, privateKey.getP());
		BigInteger hash,xr,hashxr,kinv, hashxrkinv;
		hash=toBigInt(hash(message));
		xr=privateKey.getD().multiply(r);
		hashxr=hash.subtract(xr);
		kinv=k.modInverse(privateKey.getP().subtract(ONE));
		hashxrkinv=hashxr.multiply(kinv);
		BigInteger s=hashxrkinv.mod(privateKey.getP().subtract(ONE));
		if (s.equals(ZERO)){
			return sign(message);
		}
		byte[] p1=new byte[keylength/8];
		System.arraycopy(toByteArray(r), 0, p1, keylength/8-toByteArray(r).length==0?0:1, toByteArray(r).length);
		byte[] p2 = new byte[keylength/8];
		System.arraycopy(toByteArray(s), 0, p2, keylength/8-toByteArray(s).length==0?0:1, toByteArray(s).length);
		byte[] signature=new byte[p1.length+p2.length];
		for (int i = 0; i < p1.length; i++) {
			signature[i]=p1[i];
		}
		for (int i = 0; i < p2.length; i++) {
			signature[p1.length+i]=p2[i];
		}
		return signature;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		byte[] leftSide = toByteArray(publicKey.getG().modPow(toBigInt(hash(message)),publicKey.getP()));
		byte[] p1=new byte[signature.length/2];
		byte[] p2 =new byte[signature.length/2];
		System.arraycopy(signature, 0, p1, 0, p1.length);
		System.arraycopy(signature, p1.length, p2, 0, p2.length);
		BigInteger r,s;
		r=toBigInt(p1);
		s=toBigInt(p2);
		if(r.compareTo(ZERO)<=0||r.compareTo(publicKey.getP())>=0) {
			return false;
		}
		if(s.compareTo(ZERO)<=0||s.compareTo(publicKey.getP().subtract(ONE))>=0) {
			return false;
		}
		BigInteger yr, rs,yrrs;
		yr=publicKey.getE().modPow(r, publicKey.getP());
		rs=r.modPow(s,publicKey.getP());
		yrrs=yr.multiply(rs);
		byte[] rightSide = toByteArray(yrrs.mod(publicKey.getP()));

		return Arrays.equals(leftSide, rightSide);
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