package encrypt_utils;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class EncryptUtils {

	static public String encrypt_field(String field, String key) {
		// 例如，sid可以对应到ZZXXXDDD，一一对应
		// 函数需求：明文field和密文field可以直接从字面上进行转换，从而不需要维护对应的信息表，从而把sql改写与mysql信息解耦
		String cipher_field = "";
		try {
			AESUtil a = new AESUtil(key);
			cipher_field = a.encrypt_hex(field);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// return aes(sid,key);
		return cipher_field;
	}

	static public String Eq_encrypt(int plain_int, String field_key) {
		String eq_cipher = "";
		try {
//			BlowFishUtil b = new BlowFishUtil(field_key);
			AESUtil b = new AESUtil(field_key);
			return b.encrypt("" + plain_int);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return eq_cipher;
	}

	static public String Ord_encrypt(int plain_int, int domain,int range) {
		String ord_cipher = "";
		OPEUtil o = new OPEUtil(domain, range);
		BigInteger r = o.encrypt(plain_int);
		if(r!=null){
			return r.toString();
		}
		return ord_cipher;
	}

	static public String HOM_encrypt(int plain_int,int bitLengthVal, int certainty) {
		String hom_encrypt = "";
		PaillierUtil p =new PaillierUtil(bitLengthVal, certainty);
		BigInteger b = p.Encryption(new BigInteger(""+plain_int));
		if(b!=null){
			return b.toString();
		}
		return hom_encrypt;
	}

	static public String Eq_encrypt_char(String plain_str, String field_key) {
		String eq_cipher = "";
		try {
			AESUtil b = new AESUtil(field_key);
			return b.encrypt(plain_str);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return eq_cipher;
	}

	static public void Ord_encrypt(String plain_str) {

	}

	static public void Srch_encrypt(String plain_str) {

	}

	static public void RND_encrypt(String salt) {

	}

	
	/**
	 * 获取一个随机salt值
	 * @return
	 */
	static public String getRandomIV(){
		BigInteger b = new BigInteger("11111111111");
		return b.toString();
	}
}
