package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class RCallable implements Callable<BigInteger> {
	private BigInteger pPrime,p;
	private SecureRandom s;

	public RCallable(BigInteger p,BigInteger pPrime, SecureRandom s) {
		this.pPrime=pPrime;
		this.s=s;
		this.p=p;
	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger r;
		do {
			r = (new BigInteger(pPrime.subtract(BigInteger.ONE).bitLength() + 100, s)).mod(pPrime.subtract(BigInteger.ONE));
		} while (r.equals(BigInteger.ZERO) );
		return r;
	}

}
