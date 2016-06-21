package encrypt_utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

	// SecretKey 负责保存对称密钥
	private SecretKey deskey;
	// Cipher负责完成加密或解密工作
	private Cipher c;
	// 该字节数组负责保存加密的结果
	private byte[] cipherByte;

	public AESUtil(String key) throws NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] bKey = Base64Utils.base64Decode(key);
		deskey = new SecretKeySpec(bKey, "AES");
		c = Cipher.getInstance("AES");
	}

	/**
	 * 对字符串加密
	 * 
	 * @param str
	 * @return
	 */
	private byte[] Encrytor(String str) {
		// 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式
		try {
			c.init(Cipher.ENCRYPT_MODE, deskey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] src = str.getBytes();
		// 加密，结果保存进cipherByte
		try {
			cipherByte = c.doFinal(src);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cipherByte;
	}

	/**
	 * 对字符串解密
	 * 
	 * @param buff
	 * @return
	 */
	private byte[] Decryptor(byte[] buff) {
		// 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示加密模式
		try {
			c.init(Cipher.DECRYPT_MODE, deskey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			cipherByte = c.doFinal(buff);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cipherByte;
	}

	/**
	 * 密文cipher，通过base64util进行转换成byte[]，然后解密成byte形式的明文，在转换成String
	 * 
	 * @param base64str
	 * @return
	 */
	public String decrypt(String base64str_cipher) {
		// 用base64util对String进行转换，转换成byte[]
		byte[] encontent = Base64Utils.base64Decode(base64str_cipher);
		// 解密byte形式的密文，转换成了String形式的密文
		byte[] decontent = Decryptor(encontent);
		String plain = new String(decontent);
		return plain;
	}

	/**
	 * 明文plain，加密成byte形式的密文，然后用base64util进行转换成String
	 * 
	 * @param plain
	 * @return
	 */
	public String encrypt(String plain) {
		// 加密String形式的明文，成了byte形式的密文
		byte[] encontent = Encrytor(plain);
		// 用base64util对byte进行转换，转换成String
		String base64str_cipher = Base64Utils.base64Encode(encontent);
		return base64str_cipher;
	}

	/**
	 * 生成符合AES的key，String类型，可用于该类的构造函数
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static public String GenerateKey() throws NoSuchAlgorithmException {
		// 实例化支持DES算法的密钥生成器(算法名称命名需按规定，否则抛出异常)
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		// 生成密钥
		SecretKey seckey = keygen.generateKey();
		String tmp_sk = Base64Utils.base64Encode(seckey.getEncoded());
		return tmp_sk;
	}

	public String encrypt_hex(String plain) {
		String cipher = new String();
		byte[] b = Encrytor(plain);
		cipher = ByteHexUtils.byte2hexString(b);
		return cipher;
	}

	public String decrypt_hex(String cipher) {
		String plain = new String();
		byte[] b = ByteHexUtils.hexString2byte(cipher);
		plain = new String(Decryptor(b));
		return plain;
	}

	public static void main(String[] args) throws Exception {

		String tmp_seckey = AESUtil.GenerateKey();
		System.out.println("SecretKet: " + tmp_seckey);
		AESUtil u = new AESUtil(tmp_seckey);

		String msg = "hello world";
		String cipher = u.encrypt(msg);
		System.out.println("cipher: " + cipher);
		String plain = u.decrypt(cipher);
		System.out.println("plain: " + plain);
//======================================================
		String msg2 = "sid";
//		byte[] b = u.Encrytor(msg2);
//
//		String s = ByteHexUtils.byte2hexString(b);
//		System.out.println(s);
//		byte[] bb = ByteHexUtils.hexString2byte(s);
//
//		String str = new String(u.Decryptor(bb));
//		System.out.print(str);
		String tmp = u.encrypt_hex(msg2);
		System.out.print(tmp);
		System.out.print(u.decrypt_hex(tmp));
	}

}