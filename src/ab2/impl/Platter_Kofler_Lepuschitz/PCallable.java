package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class PCallable implements Callable<BigInteger> {
	private int n;
	private SecureRandom rand;

	public PCallable(int n, SecureRandom rand) {
		this.n = n;
		this.rand = rand;
	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger p;
		do {
			p = BigInteger.probablePrime(n - 1, rand);
			p = ElGamalImpl.TWO.multiply(p).add(ElGamalImpl.ONE);
		} while (!p.isProbablePrime(40) || p.bitLength() != n);
		return p;
	}

}
