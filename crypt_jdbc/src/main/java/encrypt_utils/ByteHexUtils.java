package encrypt_utils;

/**
 * 使用AES算法加解密过程中，使用base64会出现=+-等符号，而建立表过程中SQL的表名不能接受这几个符号。
 * 主要针对的是就是上面的问题，转换成16进制进行建表操作
 * 
 * @author ch
 *
 */
public class ByteHexUtils {

	/**
	 * byte数组转换成十六进制string
	 * 
	 * @param b
	 * @return
	 */
	static public String byte2hexString(byte[] bytes) {
		String ret = "";
		for (int i = 0; i < bytes.length; i++) {
			String hex = Integer.toHexString(bytes[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			ret += hex.toUpperCase();
		}
		return ret;
	}

	/**
	 * 十六进制转换成byte数组
	 * 
	 * @param hexString
	 * @return
	 */
	static public byte[] hexString2byte(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			b[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return b;
	}

	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		// Base64 b = new Base64();
		String str = "1234567890abcdefghijklmnopqrst";
		System.out.println(str);
		byte[] b = str.getBytes();
		System.out.println(str.getBytes());
		String hexstr = byte2hexString(b);
		System.out.println(hexstr);
		byte[] buf = hexString2byte(hexstr);
		System.out.println(new String(buf));
	}

}
