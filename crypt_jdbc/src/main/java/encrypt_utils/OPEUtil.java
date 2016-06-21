package encrypt_utils;
import java.math.BigInteger;

public class OPEUtil {

	/**
	 * domain,represent 2^d numbers
	 */
	protected int domain;

	/**
	 * range,represent 2^r numbers.r>>d,eg,r=64 d=32
	 */
	protected int range;

	private BigInteger d;// 代表0-d的小区间
	private BigInteger r;// 代表0-r的大区间
	private BigInteger uint;// 单元 unit=r/d

	public OPEUtil(int domain, int range) {
		this.domain = domain;
		this.range = range;
		init();
	}

	private void init() {
		this.d = new BigInteger("1");
		this.d = this.d.shiftLeft(domain);
		this.r = new BigInteger("1");
		this.r = this.r.shiftLeft(range);
		this.uint = new BigInteger(this.r.divide(this.d).toString());
		// System.out.println("d=" + d);
		// System.out.println("r=" + r);
		// System.out.println("uint=" + uint);
	}

	/**
	 * @param low
	 * @param high
	 * @return 区间内的随机值
	 */
	private BigInteger find_random_number_from_interval(BigInteger low, BigInteger high) {
		BigInteger b = new BigInteger(high.subtract(low).toString());
		int tmp = (int) Math.round(Math.random() * 100000);
		b = b.multiply(BigInteger.valueOf(tmp));
		b = b.divide(BigInteger.valueOf(100000));
		return b.add(low);
	}

	// private int random_int_from_zero_to_hundred(){
	// return (int) Math.round(Math.random()*100);
	// }

	public BigInteger encrypt(int plain_int) {

		if (this.d.compareTo(BigInteger.valueOf(plain_int)) < 0 || plain_int < 0) {
			// domain<plain_int or plain_int<0
			System.out.println("plain_int over length!");
			return BigInteger.valueOf(0);
		} else {
			BigInteger ltmp = BigInteger.valueOf(plain_int);
			BigInteger htmp = BigInteger.valueOf(plain_int + 1);

			return find_random_number_from_interval(ltmp.multiply(this.uint), htmp.multiply(this.uint));
		}
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		OPEUtil ope = new OPEUtil(32, 64);

		System.out.println(ope.encrypt(0));
		System.out.println(ope.encrypt(1));
		for (int i = 0; i < 100; i++) {

			System.out.println("ope:(" + i + ")=" + ope.encrypt(i));
		}
	}
}
