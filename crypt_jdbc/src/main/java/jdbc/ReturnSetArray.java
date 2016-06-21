package jdbc;

import java.util.ArrayList;
import java.util.List;

public class ReturnSetArray {

	/**
	 * 列名，如sid，sname
	 */
	public List<String> columns = new ArrayList<>();
	
	/**
	 * 明文结果，如1,Alice
	 */
	public List<String> ritems = new ArrayList<>();
	
	
	public ReturnSetArray(List<String> cs,List<String> rs ) {
		for (String c : cs) {
			columns.add(c);
		}
		for (String r : rs) {
			ritems.add(r);
		}
	}
	
	
	public static void main(String[] args) {
		List<String> a = new ArrayList<>();
		a.add("sid");a.add("sname");
		List<String> b = new ArrayList<>();
		b.add("1");b.add("Alice");
		b.add("2");b.add("Bob");
		ReturnSetArray rsa = new ReturnSetArray(a, b);
		for (String c : rsa.columns) {
			System.out.println(c);
		}
		for (String r : rsa.ritems) {
			System.out.println(r);
		}
	}

}
