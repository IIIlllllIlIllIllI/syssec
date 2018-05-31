package ab2.impl.Platter_Kofler_Lepuschitz;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Rthread implements Runnable {
	BigInteger a,b;
	SecureRandom s;
	BigInteger r;
	public static boolean finish=false;
	public static BigInteger f;

	public Rthread(BigInteger b,BigInteger a, SecureRandom s) {
		finish=false;
		this.a=a;
		this.s=s;
		this.b=b;
	}
	@Override
	public void run() {
		do {
			if(finish){
				return;
			}
			r = (new BigInteger(a.subtract(BigInteger.ONE).bitLength() + 100, s)).mod(a.subtract(BigInteger.ONE));
			
		} while (r.equals(BigInteger.ZERO) );
		finish=true;
		f=r;
		System.out.println(f);
		
	}

}
