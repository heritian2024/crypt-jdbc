package KeyManage;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;

import encrypt_utils.AESUtil;
import encrypt_utils.BlowFishUtil;
import encrypt_utils.PaillierUtil;

public class KeyManager {
	// key的管理部分
	// 初步设想，保存有一个树结构，存放各种key。
	// k=PRP(table t, column c, onion o, layer l)
	// 缺陷是，
	// 原文中，列名没有任何意义，只是random字符串。改进，由每一个field和对应的key进行aes转化。最后一个salt存储的是RND的参数值，没有对应的key参与运算，故使用hash
	// 例如，aes("sid",key_sid_eq)+"oEq",aes("sid",key_sid_ord)+"oOrd",aes("sid",key_sid_add)+"oAdd",hash("sid")+"oSalt"
	// 这样，每一个cipher_field的名字不同，但是通过各自的key，可以算出来原始的值

	// 设置2个map索引，一个是洋葱列索引，另一个是列名，value存有对应的key值
	// 洋葱列索引<<"student","sid","XXX_Eq">,keyGen_Eq>，前面的3个参数存储在javabeen里面
	// 列名索引<<"student","sid">,keyGenHEX>，value的key值，可以使列名在明文密文之间转换，"sid"<->"XXX"_Eq
	static public Map<TableColumnField, String> onioncolumns = new HashMap<TableColumnField, String>();
	static public Map<TableColumn, String> columns = new HashMap<TableColumn, String>();

	/**
	 * 根据field值，获取其对应的key值 getKey("student","sid")
	 * 
	 * @param table
	 * @param column
	 * @return
	 */
	static public String getKey(String table, String column) {
		String key = columns.get(new TableColumn(table, column));
		if (key == null) {
			System.out.println("cant find key,for field and column!");
			return "";
		}
		return key;
	}

	/**
	 * 能够把"sid"转换为"XXX"_Eq 找到的结构类似<<"student","sid">,"AES_key">，然后可以计算出"XXX" we
	 * called "student" as table, "sid" as column, "XXX" as field
	 * 
	 * @param table
	 * @param column
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static public String getAESHexField(String table, String column) throws NoSuchAlgorithmException {
		// add map
		String key;
		if (!columns.containsKey(new TableColumn(table, column))) {
			key = AESUtil.GenerateKey();
			columns.put(new TableColumn(table, column), key);
		} else {
			// find key
			key = columns.get(new TableColumn(table, column));
		}
		try {
			AESUtil a = new AESUtil(key);
			String cipher = a.encrypt_hex(column);
			// add map
			if (!columns.containsKey(new TableColumn(table, cipher))) {
				columns.put(new TableColumn(table, cipher), key);
			}
			// return
			return cipher;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * 能够把"XXX"_Eq转换为"sid" 找到的结构类似<<"student","XXX">,"AES_key">，然后可以计算出"sid" we
	 * called "student" as table, "sid" as column, "XXX" as field
	 * 
	 * @param table
	 * @param field
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static public String getAESHexColumn(String table, String field) throws NoSuchAlgorithmException {
		// add map
		if (!columns.containsKey(new TableColumn(table, field))) {
			return "";
		}
		// find key
		String tmp = columns.get(new TableColumn(table, field));
		try {
			AESUtil a = new AESUtil(tmp);
			return a.decrypt_hex(field);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	static public enum FieldType {
		int_Eq, int_Ord, int_Add, char_Eq
	};

	/**
	 * 初始化Map
	 * 
	 * @param table
	 * @param column
	 * @param field
	 * @return
	 */
	static public Boolean keysInit(String table, String column, String field, FieldType f) {
		switch (f) {
//		case int_Eq:
//			// ("cryptdb_class","sid","XXX_Eq")
//			try {
//				String key = BlowFishUtil.GenerateKey();
//				onioncolumns.put(new TableColumnField(table, column, field), key);
//			} catch (NoSuchAlgorithmException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			break;
		case int_Ord:
			String ope_domain = "32";
			String ope_range = "64";
			onioncolumns.put(new TableColumnField(table, column, field), ope_domain + "," + ope_range);
			break;
		case int_Add:
			String paillier_first = "512";
			String paillier_second = "64";
			onioncolumns.put(new TableColumnField(table, column, field), paillier_first + "," + paillier_second);
			break;
		case int_Eq:
		case char_Eq:
			try {
				String key = AESUtil.GenerateKey();
				onioncolumns.put(new TableColumnField(table, column, field), key);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			break;

		default:
			return false;
		}
		return true;
	}

	/**
	 * 从Map。onioncolumns。中获取洋葱列的密钥key
	 * 
	 * @param table
	 * @param column
	 * @param field
	 * @param f
	 * @return 如果返回""，则程序出错
	 */
	static public String keysGet(String table, String column, String field, FieldType f) {
		String key = "";
		switch (f) {
//		case int_Eq:
//			key = onioncolumns.get(new TableColumnField(table, column, field));
//			break;
		case int_Ord:
			// String ope_domain = "32";
			// String ope_range = "64";
			// ope_domain + "," + ope_range
			key = onioncolumns.get(new TableColumnField(table, column, field));
			break;
		case int_Add:
			// String paillier_first = "512";
			// String paillier_second = "64";
			// paillier_first + "," + paillier_second
			key = onioncolumns.get(new TableColumnField(table, column, field));
			break;
		case int_Eq:
		case char_Eq:
			key = onioncolumns.get(new TableColumnField(table, column, field));
			break;
		default:
			break;
		}
		return key;
	}

	public static void main(String[] args) {
		columns.put(new TableColumn("student", "sid"), "8c5Bsy3REpoGyDIPWMCi/Q==");
		String str = columns.get(new TableColumn("student", "sid")).toString();
		System.out.println(str);
	}

}
