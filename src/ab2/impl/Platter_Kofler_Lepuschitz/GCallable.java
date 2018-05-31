package ab2.impl.Platter_Kofler_Lepuschitz;

import static ab2.impl.Platter_Kofler_Lepuschitz.ElGamalImpl.ONE;
import static ab2.impl.Platter_Kofler_Lepuschitz.ElGamalImpl.TWO;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class GCallable implements Callable<BigInteger> {
	private BigInteger p,pPrime;
	private SecureRandom rand;

	public GCallable(BigInteger p,BigInteger pPrime,SecureRandom rand) {
		this.p = p;
		this.pPrime=pPrime;
		this.rand = rand;

	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger g =(new BigInteger(p.bitLength() + 100, rand)).mod(p);
		while (!g.modPow(pPrime, p).equals(ONE)) {
			if (g.modPow(pPrime.multiply(TWO), p).equals(ONE))
				g = g.modPow(TWO, p);
			else
				g = (new BigInteger(p.bitLength() + 100, rand)).mod(p);
		}
		return g;
	}

}
