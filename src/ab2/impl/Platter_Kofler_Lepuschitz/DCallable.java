package ab2.impl.Platter_Kofler_Lepuschitz;

import static ab2.impl.Platter_Kofler_Lepuschitz.ElGamalImpl.ONE;
import static ab2.impl.Platter_Kofler_Lepuschitz.ElGamalImpl.ZERO;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;

public class DCallable implements Callable<BigInteger> {
	private BigInteger pPrime;
	private SecureRandom rand;

	public DCallable(BigInteger pPrime,SecureRandom rand) {
		this.pPrime=pPrime;
		this.rand = rand;

	}

	@Override
	public BigInteger call() throws Exception {
		BigInteger d;
		do {
			d = (new BigInteger(pPrime.subtract(ONE).bitLength() + 100, rand)).mod(pPrime.subtract(ONE));
		} while (d.equals(ZERO));
		return d;
	}

}
