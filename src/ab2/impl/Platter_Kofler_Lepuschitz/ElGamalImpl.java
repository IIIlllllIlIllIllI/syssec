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
		
		// initializing the bigintegers
		BigInteger p = null, d = null, g = null, pPrime;
		executorService=Executors.newFixedThreadPool(THREADS);
		
		// we are using threads to shorten the execution time
		List<Callable<BigInteger>> l = new ArrayList<>();
		
		// generating p. p and (p/2)-1 must be prime numbers.
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
		
		// pPrime = (p/2)-1 which is also a prime number
		// pPrime is a primitive root of p therefore also the order of Z/Z(p)
		pPrime = p.subtract(ONE).divide(TWO);
		l = new ArrayList<>();
		
		// generating the generator g of Z/Z(p) of order pPrime
		// g is part of the public key
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
		
		// generating d, which is a random number in {1, ..., pPrime-1}
		// d is the secret of the receiver and therefore part of the private key
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
		
		// generating e = g^d
		BigInteger e = g.modPow(d, p);
		
		// initializing the private and public key with the values calculated before
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
		
		// getting the length of the key from p, which is part of the public key
		int keylength = publicKey.getP().bitLength();
		
		// calculating the length of a block using the keylength
		int blocklength = keylength / 8 - 1;
		
		// calculating the optimal length of a cipher block
		int optimalCipherBlockLength = keylength / 8 * 2;
		
		// initializing the used bigintegers
		BigInteger r = null, s, c1, pPrime;
		
		// generating the order pPrime using p form the public key
		pPrime = publicKey.getP().subtract(BigInteger.ONE).divide(TWO);
		

		ArrayList<Byte> arrayList = new ArrayList<>();


		// dividing the data into 'blocklength' byte blocks and encrypt them
		for (int i = 0; i < data.length; i += blocklength) {
			ArrayList<Callable<BigInteger>> l = new ArrayList<>();
			
			// generating r, which is a random number in {1, ..., pPrime-1}
			// r is the secret of the sender used for the encryption
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

			// generating c1 = g^r
			// c1 is later used by the receiver in the decryption of the message
			c1 = publicKey.getG().modPow(r, publicKey.getP());
			
			// generating the secret s = e^r = g^(r*d)
			// s is the shared secret for encryption and decryption used by sender and receiver
			s = publicKey.getE().modPow(r, publicKey.getP());
			
			// making c1 into a byteArray so that we can send it
			byte[] c1Bytes = toByteArray(c1);
			
			// we pad the array until we reach the optimal block length for the cipher block
			for (int j = 0; j < optimalCipherBlockLength/2-c1Bytes.length; j++) {
				arrayList.add((byte) 0);
			}
			for (int j = 0; j < c1Bytes.length; j++) {
				arrayList.add(c1Bytes[j]);
			}
			
			// initializing a byteArray for the fragments of the message
			byte[] m_i = new byte[blocklength + 1];
			
			// calculating the length of the last block. Used for padding
			int lenLastBlock = data.length - i;

			// check if the last block is shorter than 127 bytes
			if (blocklength < lenLastBlock) {
				lenLastBlock = blocklength;
			}
			m_i[0]=(byte) (blocklength-lenLastBlock+1);

			// copying a designated part of the data of the message into our m_i
			System.arraycopy(data, i, m_i, m_i.length - lenLastBlock, lenLastBlock);
			
			// generating c2 = m_i * s
			// this is the encryption of the current block
			m_i=toByteArray(toBigInt(m_i).multiply(s).mod(publicKey.getP()));
			
			// padding
			for (int j = 0; j < optimalCipherBlockLength/2-m_i.length; j++) {
				arrayList.add((byte) 0);
			}

			// copying the encrypted block of the message into our array
			// this way we get (c1,c2), which the sender sends to the receiver
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

	
	// similar to the encryption but in reverse order
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
			
			// filter c1 out of the array because we need it to generate the shared secret s
			System.arraycopy(data, i, c1_i, 0, c1_i.length);
			BigInteger c1 = toBigInt(c1_i);
			
			// generating s = c1^d
			BigInteger s = c1.modPow(privateKey.getD(), privateKey.getP());
			byte[] c2_i = new byte[optimalCipherBlockLength/2];

			// filtering c2 out of the array
			System.arraycopy(data, i+optimalCipherBlockLength/2, c2_i, 0, c2_i.length);

			// decrypt the block
			//m_i = c2_i * s^-1
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
		
		// generating a secret key k in {1,...,p-2}
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
		
		// generating r = g^x % p
		r=privateKey.getG().modPow(k, privateKey.getP());
		
		BigInteger hash,xr,hashxr,kinv, hashxrkinv;
		
		// hashing the message
		hash=toBigInt(hash(message));
		
		xr=privateKey.getD().multiply(r);
		
		// hashxr = H(m) - xr
		hashxr=hash.subtract(xr);
		
		// kinv = k^-1
		kinv=k.modInverse(privateKey.getP().subtract(ONE));
		
		// hashxrkinv = (H(m) - xr)*k^-1
		hashxrkinv=hashxr.multiply(kinv);
		
		// calculating s = (H(m) - xr)*k^-1  (mod p-1)
		BigInteger s=hashxrkinv.mod(privateKey.getP().subtract(ONE));
		
		// we have to start over if s = 0
		if (s.equals(ZERO)){
			return sign(message);
		}
		
		// the signature is composed of the pair r and s
		byte[] p1=new byte[keylength/8];
		System.arraycopy(toByteArray(r), 0, p1, keylength/8-toByteArray(r).length==0?0:1, toByteArray(r).length);
		
		byte[] p2 = new byte[keylength/8];
		System.arraycopy(toByteArray(s), 0, p2, keylength/8-toByteArray(s).length==0?0:1, toByteArray(s).length);
		
		// signature = (r, s)
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
		
		// leftSide = g^H(m)  (mod p)
		byte[] leftSide = toByteArray(publicKey.getG().modPow(toBigInt(hash(message)),publicKey.getP()));
		
		// filtering r and s out of the signature
		byte[] p1=new byte[signature.length/2];
		byte[] p2 =new byte[signature.length/2];
		
		System.arraycopy(signature, 0, p1, 0, p1.length);
		System.arraycopy(signature, p1.length, p2, 0, p2.length);
		
		BigInteger r,s;
		r=toBigInt(p1);
		s=toBigInt(p2);
		
		// if 0 < r < p is not given, then the signature gets rejected
		if(r.compareTo(ZERO)<=0||r.compareTo(publicKey.getP())>=0) {
			return false;
		}
		
		// if 0 < s < p-1 is not given, then the signature gets rejected
		if(s.compareTo(ZERO)<=0||s.compareTo(publicKey.getP().subtract(ONE))>=0) {
			return false;
		}
		
		BigInteger yr, rs,yrrs;
		
		// yr = e^r  (mod p)
		yr=publicKey.getE().modPow(r, publicKey.getP());
		
		// rs = r^s  (mod p)
		rs=r.modPow(s,publicKey.getP());
		
		// yrrs = e^r * r^s
		yrrs=yr.multiply(rs);
		
		// rightSide = yrrs
		byte[] rightSide = toByteArray(yrrs.mod(publicKey.getP()));

		// if g^H(m) = e^r * r^s  (mod p) is not given, then the signature gets rejected
		return Arrays.equals(leftSide, rightSide);
	}

	// funciton to convert a byteArray into a biginteger
	private static BigInteger toBigInt(byte[] arr) {
		return new BigInteger(1, arr);
	}

	
	// function to convert a biginteger into a byteArray
	private static byte[] toByteArray(BigInteger bi) {
		byte[] array = bi.toByteArray();
		if (array[0] == 0) {
			byte[] tmp = new byte[array.length - 1];
			System.arraycopy(array, 1, tmp, 0, tmp.length);
			array = tmp;
		}
		return array;
	}
	
	// hash funciton
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