package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class RCallable implements Callable<BigInteger> {
	private BigInteger a,b;
	private SecureRandom s;

	public RCallable(BigInteger b,BigInteger a, SecureRandom s) {
		this.a=a;
		this.s=s;
		this.b=b;
	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger r;
		do {
			r = (new BigInteger(a.subtract(BigInteger.ONE).bitLength() + 100, s)).mod(a.subtract(BigInteger.ONE));
		} while (r.equals(BigInteger.ZERO) );
		return r;
	}

}
