package encrypt_utils;

import org.apache.commons.codec.binary.Base64;

public class Base64Utils {
	public static String base64Encode(String data) {
		return Base64.encodeBase64String(data.getBytes());
	}

	public static String base64Encode(byte[] data) {
		return Base64.encodeBase64String(data);
	}

	public static byte[] base64Decode(String data) {
		return Base64.decodeBase64(data.getBytes());
	}

	public static void main(String[] args) {
		// Base64 b = new Base64();
//		String str = "1234567890abcdefghijklmnopqrstaaaa";
//		System.out.println(str);
//		System.out.println(str.getBytes());
//		String base64str = base64Encode(str);
//		System.out.println(base64str);
//		byte[] buf = base64Decode(base64str);
//		System.out.println(new String(buf));
		String a ="U2FsdGVkX1+GwIYSkb6ewlmShIAAR+k1oKV87HFVoZlaCLjKUa3RsXxMIzs88xv2gvX9wXRao4SLaiOyB8I13w==";
		byte[] buf = base64Decode(a);
		
		String i = new String(buf);
		System.out.println(i);
		
		int l = i.indexOf(';');
		String salted1 =i.substring(9,l);
		String salted2 =i.substring(l+1,i.length());
		
		System.out.println(buf);
	}

}
