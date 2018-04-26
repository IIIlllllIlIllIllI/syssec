package ab1.impl.Nachnamen;

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
	private int bitlength;
	private static final String HASH_FUNCTION="SHA-256";

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
		ArrayList<Byte> al=new ArrayList<>();
		byte[] result;
		for (int i = 0; i < data.length; i+=127) {
			byte[] tmp = new byte[128];
			int lenLastBlock=data.length-i;
			if(!(127>lenLastBlock)){
				lenLastBlock=127;
			}
		    System.arraycopy(data, i, tmp, tmp.length-lenLastBlock, lenLastBlock);
		    tmp[0]=(byte) (tmp.length-lenLastBlock+1);
		    
//		    if(tmp.length<127){
//		    	byte[] padding=new byte[127];
//		    	
//		    	System.arraycopy(tmp, 0, padding, 0, tmp.length);
//		    	padding[tmp.length]=1;
//		    	if(tmp.length==127){
//		    		tmp=new byte[padding.length*2];
//		    	}else{
//		    		tmp=new byte[padding.length];
//		    	}
//		    	System.arraycopy(padding, 0, tmp, 0, padding.length);
//		    }
		    tmp=toByteArray((toBigInt(tmp).modPow(publicKey.getE(), publicKey.getN())));
		    for (int j = 0; j < tmp.length; j++) {
				al.add(tmp[j]);
			}
		}
		result=new byte[al.size()];
		for (int i = 0; i < al.size(); i++) {
			result[i]=al.get(i);
		}
		System.out.println(Arrays.toString(data));
		System.out.println(Arrays.toString(result));
		return result;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		ArrayList<Byte> al=new ArrayList<>();
		byte[] result;
		for (int i = 0; i < data.length; i+=128) {
			byte[] tmp = new byte[128];
		    System.arraycopy(data, i, tmp, 0, tmp.length);
//		    if(tmp[tmp.length-1]==0){
//		    	int idx=tmp.length-1;
//		    	while(tmp[idx]==0){
//		    		idx--;
//		    		if(idx<0)
//		    			break;
//		    	}
//		    	if(idx>=0&&tmp[idx]==1){
//		    		byte[] nopadding=new byte[idx];
//		    		System.arraycopy(tmp, 0, nopadding, 0, nopadding.length);
//		    		tmp=nopadding;
//		    	}
//		    }
		    tmp=toByteArray((toBigInt(tmp).modPow(privateKey.getD(), privateKey.getN())));
		    
		    for (int j = 0; j < tmp.length; j++) {
				al.add(tmp[j]);
			}
		}
		result=new byte[al.size()];
		for (int i = 0; i < al.size(); i++) {
			result[i]=al.get(i);
		}
		System.out.println(Arrays.toString(data));
		System.out.println(Arrays.toString(result));
		return result;
	}

	@Override
	public byte[] sign(byte[] message) {
		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_FUNCTION);
			message=digest.digest(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] result=decrypt(message);
		return result;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		byte[] result=encrypt(message, false);
		try {
			MessageDigest digest = MessageDigest.getInstance(HASH_FUNCTION);
			message=digest.digest(message);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		System.out.println(Arrays.equals(message,result));
		return Arrays.equals(message,result);
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
