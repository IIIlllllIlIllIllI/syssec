package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class KCallable implements Callable<BigInteger> {
	private BigInteger p;
	private SecureRandom s;

	public KCallable(BigInteger p, SecureRandom s) {
		this.s=s;
		this.p=p;
	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger r;
		do {
			r = (new BigInteger(p.subtract(BigInteger.ONE).bitLength() + 100, s)).mod(p.subtract(BigInteger.ONE));
		} while (r.compareTo(ElGamalImpl.ONE)<=0||r.compareTo(p.subtract(ElGamalImpl.ONE))>=0||!(r.gcd(p.subtract(BigInteger.ONE)).equals(ElGamalImpl.ONE)));
		return r;
	}

}
