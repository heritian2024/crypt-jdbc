package jdbc;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

import KeyManage.KeyManager;
import Maven.jsqlparser_test.ParserMain;
import encrypt_utils.AESUtil;
import encrypt_utils.BlowFishUtil;
import encrypt_utils.EncryptUtils;
import net.sf.jsqlparser.statement.select.First.Keyword;

public class jdbc_crypt {

	// JDBC driver name and database URL
	static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
	// static final String DB_URL = "jdbc:mysql://localhost/jdbc_test";
	static String DB_URL = null;// DB_URL+IP+DB
	// Database credentials
	static final String USER = "root";
	static final String PASS = "";
	// 中间结构
	static Connection conn = null;
	static PreparedStatement pstmt = null;

	/**
	 * 初始化jdbc
	 * 
	 * @param ip
	 * @param db
	 */
	public jdbc_crypt(String ip, String db) {
		DB_URL = new String("jdbc:mysql://" + ip + "/" + db);
		// 从文件中加载表table的信息
	}

	/**
	 * 获取connection
	 * 
	 * @return
	 */
	private static Connection getConn() {
		try {
			Class.forName(JDBC_DRIVER); // classLoader,加载对应驱动
			conn = (Connection) DriverManager.getConnection(DB_URL, USER, PASS);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return conn;
	}

	/**
	 * 执行sql语句，返回结果集 方法executeQuery 用于产生单个结果集的语句，例如 SELECT语句。
	 * 
	 * @param sql
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public ReturnSetArray executeQuery(String sql) throws NoSuchAlgorithmException, NoSuchPaddingException {
		Connection conn = getConn();
		PreparedStatement pstmt;
		try {
			String new_sql = rewriteSQL(sql);
			// 获取table
			String table = "";
			if (new_sql.contains("where")) {
				table = new_sql.substring(new_sql.indexOf("from") + 4, new_sql.indexOf("where")).replace(" ", "");
			} else {
				table = new_sql.substring(new_sql.indexOf("from") + 4, new_sql.length()).replace(" ", "");
			}
			// 获取明文columns、密文fields和对应的key值
			List<String> columns = new ArrayList<String>();
			List<String> fields = new ArrayList<String>();
			List<String> keys = new ArrayList<String>();
			String tmp = new_sql.substring(7, new_sql.indexOf("from")).replace(" ", "");
			String[] tmp_args = tmp.split(",");
			for (String s : tmp_args) {
				if (s.contains(".")) {
					// student.XXXoEq
					String[] tmp1 = s.split("\\.");
					String field = tmp1[1];
					fields.add(field);
					String column = KeyManager.getAESHexColumn(table, tmp1[1].substring(0, tmp1[1].length() - 3));
					columns.add(column);
					String key = KeyManager.keysGet(table, column, tmp1[1], KeyManager.FieldType.int_Eq);
					keys.add(key);
				} else {
					/// XXXoEq
					String field = s;
					fields.add(field);
					String column = KeyManager.getAESHexColumn(table, s.substring(0, s.length() - 3));
					columns.add(column);
					String key = KeyManager.keysGet(table, column, s, KeyManager.FieldType.int_Eq);
					keys.add(key);
				}
			}
			// 构造ReturnSetArray
			// ReturnSetArray r = new ReturnSetArray(cs, rs)
			List<String> ritems = new ArrayList<>();
			// 重写sql语句
			pstmt = (PreparedStatement) conn.prepareStatement(new_sql);
			ResultSet rs_tmp = pstmt.executeQuery();
			// 获取有几个列，如sid、sname，有2个列
			int length = columns.size();
			if (columns.size() != keys.size()) {
				System.out.println("Size Error!");
				return null;
			}
			while (rs_tmp.next()) {
				for (int i = 0; i < length; i++) {
					String cipher = rs_tmp.getString(fields.get(i));
					// BlowFishUtil b = new BlowFishUtil(keys.get(i));
					AESUtil b = new AESUtil(keys.get(i));
					String plain = b.decrypt(cipher);
					ritems.add(plain);
				}
			}
			return new ReturnSetArray(columns, ritems);
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 方法executeUpdate 用于执行 INSERT、UPDATE或 DELETE语句以及DDL（数据定义语言）语句， 例如 CREATE
	 * TABLE和 DROP TABLE。 INSERT、UPDATE或
	 * DELETE语句的效果是修改表中零行或多行中的一列或多列。executeUpdate的返回值是一个整数，指示受影响的行数（即更新计数）。 对于
	 * CREATE TABLE 或 DROP TABLE 等不操作行的语句，executeUpdate 的返回值总为零。
	 * 
	 * @param sql
	 * @return 改变的行数
	 */
	public int executeUpdate(String sql) {
		Connection conn = getConn();
		PreparedStatement pstmt;
		int i = 0;
		try {
			pstmt = (PreparedStatement) conn.prepareStatement(rewriteSQL(sql));// 重写sql语句
			i = pstmt.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return i;
	}

	/**
	 * 重写sql
	 * 
	 * @param sql
	 * @return
	 */
	public String rewriteSQL(String sql) {

		// 解析sql语句，并改写成密文sql
		// 完成一次sql过程中，需要进行执行和返回，故有一些共享信息
		String newsql = ParserMain.Parser_Main(sql);
		System.out.println(newsql);
		return newsql;
	}

	/**
	 * 重写结果集
	 * 
	 * @param rs
	 * @return
	 */
	public ResultSet rewriteResultSet(ResultSet rs) {

		// 根据共享信息，进行解密

		return rs;
	}

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws SQLException
	 * @throws IOException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, SQLException, IOException {
		/*
		 * jdbc_crypt j = new jdbc_crypt("localhost", "jdbc_test"); String sql1
		 * =
		 * "create table student(sid int not null,sname varchar(20) not null);";
		 * String sql2 = "insert into student(sid,sname) values(1,'Alice');";
		 * String sql3 = "insert into student(sid,sname) values(2,'Bob');";
		 * String sql4 = "insert into student(sid,sname) values(3,'Alice');";
		 * int i1 = j.executeUpdate(sql1); System.out.println(i1 +
		 * " line has changed"); int i2 = j.executeUpdate(sql2);
		 * System.out.println(i2 + " line has changed"); int i3 =
		 * j.executeUpdate(sql3); System.out.println(i3 + " line has changed");
		 * int i4 = j.executeUpdate(sql4); System.out.println(i4 +
		 * " line has changed"); //select String sql =
		 * "SELECT sid,sname FROM student"; ReturnSetArray rs =
		 * j.executeQuery(sql); int clength = rs.columns.size();// 列的个数 int
		 * rlength = rs.ritems.size();// 元素的个数 for (String c : rs.columns) {
		 * System.out.print(c + "\t"); } System.out.print("\n"); for (int i = 0;
		 * i < rlength; i += clength) { for (int k = 0; k < clength; k++) { int
		 * location = i + k; System.out.print(rs.ritems.get(location) + "\t"); }
		 * System.out.print("\n"); }
		 */

		test_select(100, 1);
		
	}
	
	static void test_select(int ndata, int nselect ) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException{
	/////// select
			// 2个参数
//			int ndata = 50;
//			int nselect = 10;
			//
			String fileName = "C:/Users/ch/Desktop/data" + ndata + "_select" + nselect + ".sql";
			File f = new File(fileName);
			FileWriter fw = new FileWriter(f);
			//
			jdbc_crypt j = new jdbc_crypt("localhost", "jdbc_test");
			String sql1 = "create table student(sid int not null,sname varchar(20) not null);";fw.write(sql1+"\n");
			int i1 = j.executeUpdate(sql1);
			System.out.println(i1 + " line has changed");

			for (int i = 0; i < ndata; i++) {
				String sql = "insert into student(sid,sname) values(" + i + ",'Alice" + i + "');\n";fw.write(sql+"\n");
				int l = j.executeUpdate(sql);
				System.out.println(l + " line has changed");
			}
			// select
			// 获取开始时间
			long startTime = System.currentTimeMillis();
			System.out.println("=====>" + startTime);
			for (int i = 0; i < nselect; i++) {
				String sql = "SELECT sid,sname FROM student";fw.write(sql+";\n");
				ReturnSetArray rs = j.executeQuery(sql);
				int clength = rs.columns.size();// 列的个数
				int rlength = rs.ritems.size();// 元素的个数
				for (String c : rs.columns) {
					System.out.print(c + "\t");
				}
				System.out.print("\n");
				for (int i11 = 0; i11 < rlength; i11 += clength) {
					for (int k = 0; k < clength; k++) {
						int location = i11 + k;
						System.out.print(rs.ritems.get(location) + "\t");
					}
					System.out.print("\n");
				}
			}
			// 获取结束时间
			long endTime = System.currentTimeMillis();
			System.out.println("=====>" + endTime);
			System.out.println("程序运行时间： " + (endTime - startTime) + "ms");
			//
			fw.close();
	}

	void test() {
		/////// create
		// jdbc_crypt j = new jdbc_crypt("localhost", "jdbc_test");
		// long startTime = System.currentTimeMillis(); // 获取开始时间
		// System.out.println("=====>" + startTime);
		// for (int i = 0; i < 30; i++) {
		// String sql = "create table TT3" + i + "(sid int not null,sname
		// varchar(20) not null);";
		// int l = j.executeUpdate(sql);
		// System.out.println(l + " line has changed");
		// }
		// long endTime = System.currentTimeMillis(); // 获取结束时间
		// System.out.println("=====>" + endTime);
		// System.out.println("程序运行时间： " + (endTime - startTime) + "ms");

		/////// create
		// try{
		// String fileName = "C:/Users/ch/Desktop/create30.sql";
		// File f = new File(fileName);
		// FileWriter fw= new FileWriter(f);
		// for (int i = 0; i < 30; i++) {
		// String sql = "create table zzz11" + i + "(sid int not null,sname
		// varchar(20) not null);\n";
		// fw.write(sql);
		// }
		// fw.close();
		// }catch(IOException e){
		// }

		/////// insert
		// jdbc_crypt j = new jdbc_crypt("localhost", "jdbc_test");
		// String sql1 = "create table student(sid int not null,sname
		// varchar(20) not null);";
		// int i1 = j.executeUpdate(sql1);
		// System.out.println(i1 + " line has changed");
		// long startTime = System.currentTimeMillis(); // 获取开始时间
		// System.out.println("=====>" + startTime);
		// for (int i = 0; i < 50; i++) {
		// String sql = "insert into student(sid,sname) values(" + i + ",'Alice"
		// + i + "');\n";
		// int l = j.executeUpdate(sql);
		// System.out.println(l + " line has changed");
		// }
		// long endTime = System.currentTimeMillis(); // 获取结束时间
		// System.out.println("=====>" + endTime);
		// System.out.println("程序运行时间： " + (endTime - startTime) + "ms");

		// try{
		// String fileName = "C:/Users/ch/Desktop/insert50.sql";
		// File f = new File(fileName);
		// FileWriter fw= new FileWriter(f);
		// for (int i = 0; i < 50; i++) {
		// String sql = "insert into student(sid,sname)
		// values("+i+",'Alice"+i+"');\n";
		// fw.write(sql);
		// }
		// fw.close();
		// }catch(IOException e){
		// }
	}
}
