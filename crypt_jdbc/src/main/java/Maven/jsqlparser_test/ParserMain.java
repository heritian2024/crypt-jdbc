package Maven.jsqlparser_test;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import KeyManage.KeyManager;
import KeyManage.TableColumn;
import KeyManage.TableColumnField;
import encrypt_utils.AESUtil;
import encrypt_utils.BlowFishUtil;
import encrypt_utils.EncryptUtils;
import encrypt_utils.OPEUtil;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.expression.Expression;
import net.sf.jsqlparser.expression.operators.conditional.AndExpression;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.schema.Table;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.statement.create.table.ColDataType;
import net.sf.jsqlparser.statement.create.table.ColumnDefinition;
import net.sf.jsqlparser.statement.create.table.CreateTable;
import net.sf.jsqlparser.statement.delete.Delete;
import net.sf.jsqlparser.statement.drop.Drop;
import net.sf.jsqlparser.statement.insert.Insert;
import net.sf.jsqlparser.statement.replace.Replace;
import net.sf.jsqlparser.statement.select.AllColumns;
import net.sf.jsqlparser.statement.select.AllTableColumns;
import net.sf.jsqlparser.statement.select.Join;
import net.sf.jsqlparser.statement.select.PlainSelect;
import net.sf.jsqlparser.statement.select.Select;
import net.sf.jsqlparser.statement.select.SelectBody;
import net.sf.jsqlparser.statement.select.SelectExpressionItem;
import net.sf.jsqlparser.statement.select.SelectItem;
import net.sf.jsqlparser.statement.select.SelectItemVisitor;
import net.sf.jsqlparser.statement.select.WithItem;
import net.sf.jsqlparser.statement.update.Update;

/**
 * Hello world!
 *
 */
public class ParserMain {

	static public String visit(Insert statement) {
		// crypt statement
		List<String> new_l_columns = new ArrayList<String>();
		List<String> new_l_items = new ArrayList<String>();
		// statement has 3 parts,columns,itemsList,table
		String table_name = statement.getTable().getName();
		String tmp = statement.getItemsList().toString();
		tmp = tmp.replace("(", "");
		tmp = tmp.replace(")", "");
		String[] args = tmp.split(",");

		for (int i = 0; i < statement.getColumns().size(); i++) {
			// for each column, rewrite the item
			String colunm = statement.getColumns().get(i).getColumnName();
			// 找到第一个非空字符
			char tmp1[] = args[i].toCharArray();
			char tmp2 = ' ';
			for (int ii = 0; ii < tmp1.length; ii++) {
				if (tmp1[ii] != ' ') {
					tmp2 = tmp1[ii];
					break;
				}
			}
			// 找到开头的字符，如'Alice'的',"Alice"的"
			if (tmp2 == ' ') {
				return "";
			}
			if (tmp2 != '\'' && tmp2 != '\"') {
				// int
				// get item-----------------------------
				int item = Integer.parseInt(args[i]);
				// -------------------------------------
				// 1Eq
				String int_eq_field = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm)) + "oEq";// 计算出Eq列的名称
				// 在map索引中获取洋葱列的加密key
				String eq_field_key = KeyManager.onioncolumns
						.get(new TableColumnField(table_name, colunm, int_eq_field));
				String int_eq = EncryptUtils.Eq_encrypt(item, eq_field_key);// 计算出item对应的值
				new_l_columns.add(int_eq_field);
				new_l_items.add("\'" + int_eq + "\'");
				// 2Ord
				String int_ord_field = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm))
						+ "oOrd";// 计算出Eq列的名称
				// 在map索引中获取洋葱列的加密key
				String ord_field_key = KeyManager.onioncolumns
						.get(new TableColumnField(table_name, colunm, int_ord_field));
				String[] num_ord = ord_field_key.split(",");
				String int_ord = EncryptUtils.Ord_encrypt(item, Integer.valueOf(num_ord[0]),
						Integer.valueOf(num_ord[1]));// 计算出item对应的值
				new_l_columns.add(int_ord_field);
				new_l_items.add(int_ord);
				// 3Add
				String int_add_field = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm))
						+ "oAdd";// 计算出Eq列的名称
				// 在map索引中获取洋葱列的加密key
				String add_field_key = KeyManager.onioncolumns
						.get(new TableColumnField(table_name, colunm, int_add_field));
				String[] num_add = add_field_key.split(",");
				String int_add = EncryptUtils.HOM_encrypt(item, Integer.valueOf(num_add[0]),
						Integer.valueOf(num_add[1]));// 计算出item对应的值
				new_l_columns.add(int_add_field);
				new_l_items.add("\'" + int_add + "\'");
				// 4salt
				String int_IV = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm)) + "oSalt";
				String IV = EncryptUtils.getRandomIV();
				new_l_columns.add(int_IV);
				new_l_items.add(IV);
			} else {
				// String
				// get item-----------------------------
				Pattern p = Pattern.compile(".*[\'|\"](.*?)[\'|\"]");
				Matcher m = p.matcher(args[i]);
				ArrayList<String> strs = new ArrayList<String>();
				while (m.find()) {
					strs.add(m.group(1));
				}
				// for (String s : strs) {
				// System.out.println(s);
				// }
				String item = strs.get(0);
				// -------------------------------------
				// 1Eq
				String char_eq_field = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm))
						+ "oEq";// 计算出Eq列的名称
				// 在map索引中获取洋葱列的加密key
				String eq_field_key = KeyManager.onioncolumns
						.get(new TableColumnField(table_name, colunm, char_eq_field));
				String char_eq = EncryptUtils.Eq_encrypt_char(item, eq_field_key);// 计算出item对应的值
				new_l_columns.add(char_eq_field);
				new_l_items.add("\'" + char_eq + "\'");
				// 2salt
				String char_IV = EncryptUtils.encrypt_field(colunm, KeyManager.getKey(table_name, colunm)) + "oSalt";
				String IV = EncryptUtils.getRandomIV();
				new_l_columns.add(char_IV);
				new_l_items.add(IV);
			}

		}
		// 连接fields
		String fields = "";
		for (String s : new_l_columns) {
			fields += s;
			fields += ",";
		}
		String tmpfields = new String(fields.substring(0, fields.length() - 1));
		// 连接values
		String values = "";
		for (String s : new_l_items) {
			values += s;
			values += ",";
		}
		String tmpvalues = new String(values.substring(0, values.length() - 1));
		// 拼凑新的sql
		String new_sql = "INSERT INTO " + table_name + "(" + tmpfields + ")values(" + tmpvalues + ")";
		System.out.println(new_sql);
		return new_sql;
	}

	static public String visit(Select statement) {
		System.out.println(statement.toString());

		SelectBody s = statement.getSelectBody();
		if (s instanceof PlainSelect) {
			PlainSelect p = (PlainSelect) s;
			String tableName = p.getFromItem().toString();
			// 获取select和from中间的items
			List<String> sel_items = new ArrayList<String>();
			List<SelectItem> l = p.getSelectItems();
			for (SelectItem selectItem : l) {
				// 注意selectItem有可能是s.sid形式
				String tmp = selectItem.toString();
				if (tmp.contains(" as ")) {
					tmp = new String(tmp.substring(0, tmp.indexOf(" as ")));
				}
				String new_item = "";
				// 改写
				String[] t = tmp.split("\\.");
				switch (t.length) {
				case 1:
					// id
					String item_column = t[0];
					String field = EncryptUtils.encrypt_field(item_column, KeyManager.getKey(tableName, item_column))
							+ "oEq";
					new_item = tableName + "." + field;
					break;
				case 2:
					// s.id
					String tableName1 = t[0];
					String item_column1 = t[1];
					String field1 = EncryptUtils.encrypt_field(item_column1,
							KeyManager.getKey(tableName1, item_column1)) + "oEq";
					new_item = tableName1 + "." + field1;
					break;
				case 3:
					// db.s.id
					String tableName2 = t[1];
					String item_column2 = t[2];
					String field2 = EncryptUtils.encrypt_field(item_column2,
							KeyManager.getKey(tableName2, item_column2)) + "oEq";
					new_item = tableName2 + "." + field2;
					break;
				default:
					break;
				}
				sel_items.add(new_item);
			}
			// 获取from中的表，按照顺序
			List<String> join = new ArrayList<String>();
			join.add(tableName);
			if (p.getJoins() != null) {
				join.add(p.getFromItem().toString());
				for (Join j : p.getJoins()) {
					join.add(j.toString());
				}
			}
			// where子句
			Expression w = (Expression) p.getWhere();
			if (w != null) {
				String[] args = w.toString().replace(" ", "").split("AND");
				// 获取改写后的where expression
				List<String> new_where = new ArrayList<String>();
				for (String operation : args) {
					if (operation.contains("=")) {
						String[] expression = operation.split("=");
						String left = expression[0];
						String right = expression[1];
						if (left.contains(".")) {
							// 如果左值中包含.，即db.student.id，则分隔，并改写成新的operation
							String[] l1 = left.split("\\.");
							if (l1.length == 2) {
								String table = l1[0];
								String column = l1[1];
								String new_table_name = table;
								String new_field_name;
								try {
									// 把s.sid转换成s.XXXEq
									new_field_name = KeyManager.getAESHexField(table, column) + "oEq";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid=2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Eq);
									if (key.equals("")) {
										return "";
									}
									//BlowFishUtil b = new BlowFishUtil(key);
									AESUtil b = new AESUtil(key);
									String new_value = b.encrypt(num).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + "=\'" + new_value + "\'";
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
									e.printStackTrace();
								}
							} else if (l1.length == 3) {
								String table = l1[1];
								String column = l1[2];
								String new_table_name = table;
								String new_field_name;
								try {
									new_field_name = KeyManager.getAESHexField(table, column) + "oEq";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid=2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Eq);
									if (key.equals("")) {
										return "";
									}
									//BlowFishUtil b = new BlowFishUtil(key);
									AESUtil b = new AESUtil(key);
									String new_value = b.encrypt(num).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + "=\'" + new_value + "\'";
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						} else {
							// 不包含.，如sid=2
							String table = tableName;
							String column = left;
							String new_table_name = table;
							String new_field_name;
							try {
								new_field_name = KeyManager.getAESHexField(table, column) + "oEq";
								String new_op = new_table_name + "." + new_field_name;
								System.out.println(new_op);
								// 加密s.sid=2中的2
								String num = right;
								String key = KeyManager.keysGet(table, column, new_field_name,
										KeyManager.FieldType.int_Eq);
								if (key.equals("")) {
									return "";
								}
								//BlowFishUtil b = new BlowFishUtil(key);
								AESUtil b = new AESUtil(key);
								String new_value = b.encrypt(num).toString();
								System.out.println(new_value);
								// 拼接字符串
								String new_st = new_op + "=\'" + new_value + "\'";
								System.out.println(new_st);
								// 添加到list中
								new_where.add(new_st);
							} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						System.out.println(left + " " + right);
					} else if (operation.contains("<")) {
						String[] expression = operation.split("<");
						String left = expression[0];
						String right = expression[1];
						if (left.contains(".")) {
							// 如果左值中包含.，即db.student.id，则分隔，并改写成新的operation
							String[] l2 = left.split("\\.");
							if (l2.length == 2) {
								String table = l2[0];
								String column = l2[1];
								String new_table_name = table;
								String new_field_name;
								try {
									// 把s.sid转换成s.XXXOrd
									new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid>2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Ord);
									if (key.equals("")) {
										return "";
									}
									String[] tmpkey = key.split(",");
									int a = Integer.valueOf(tmpkey[0]);
									int b = Integer.valueOf(tmpkey[1]);
									OPEUtil o = new OPEUtil(a, b);
									String new_value = o.encrypt(Integer.valueOf(num)).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + "<" + new_value;
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							} else if (l2.length == 3) {
								String table = l2[1];
								String column = l2[2];
								String new_table_name = table;
								String new_field_name;
								try {
									new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid>2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Ord);
									if (key.equals("")) {
										return "";
									}
									String[] tmpkey = key.split(",");
									int a = Integer.valueOf(tmpkey[0]);
									int b = Integer.valueOf(tmpkey[1]);
									OPEUtil o = new OPEUtil(a, b);
									String new_value = o.encrypt(Integer.valueOf(num)).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + "<" + new_value;
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException e) {
									e.printStackTrace();
								}
							}
						} else {
							//
							// 左值不包含.，如sid>1获取sid=1
							String table = tableName;
							String column = left;
							String new_table_name = table;
							String new_field_name;
							try {
								new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
								String new_op = new_table_name + "." + new_field_name;
								System.out.println(new_op);
								// 加密s.sid>2中的2
								String num = right;
								String key = KeyManager.keysGet(table, column, new_field_name,
										KeyManager.FieldType.int_Ord);
								if (key.equals("")) {
									return "";
								}
								String[] tmpkey = key.split(",");
								int a = Integer.valueOf(tmpkey[0]);
								int b = Integer.valueOf(tmpkey[1]);
								OPEUtil o = new OPEUtil(a, b);
								String new_value = o.encrypt(Integer.valueOf(num)).toString();
								System.out.println(new_value);
								// 拼接字符串
								String new_st = new_op + "<" + new_value;
								System.out.println(new_st);
								// 添加到list中
								new_where.add(new_st);
							} catch (NoSuchAlgorithmException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						System.out.println(left + " " + right);
					} else if (operation.contains(">")) {
						String[] expression = operation.split(">");
						String left = expression[0];
						String right = expression[1];
						if (left.contains(".")) {
							// 如果左值中包含.，即db.student.id，则分隔，并改写成新的operation
							String[] l3 = left.split("\\.");
							if (l3.length == 2) {
								// student.id
								String table = l3[0];
								String column = l3[1];
								String new_table_name = table;
								String new_field_name;
								try {
									// 把s.sid转换成s.XXXOrd
									new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid>2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Ord);
									if (key.equals("")) {
										return "";
									}
									String[] tmpkey = key.split(",");
									int a = Integer.valueOf(tmpkey[0]);
									int b = Integer.valueOf(tmpkey[1]);
									OPEUtil o = new OPEUtil(a, b);
									String new_value = o.encrypt(Integer.valueOf(num)).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + ">" + new_value;
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							} else if (l3.length == 3) {
								// db.student.id
								String table = l3[1];
								String column = l3[2];
								String new_table_name = table;
								String new_field_name;
								try {
									new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
									String new_op = new_table_name + "." + new_field_name;
									System.out.println(new_op);
									// 加密s.sid>2中的2
									String num = right;
									String key = KeyManager.keysGet(table, column, new_field_name,
											KeyManager.FieldType.int_Ord);
									if (key.equals("")) {
										return "";
									}
									String[] tmpkey = key.split(",");
									int a = Integer.valueOf(tmpkey[0]);
									int b = Integer.valueOf(tmpkey[1]);
									OPEUtil o = new OPEUtil(a, b);
									String new_value = o.encrypt(Integer.valueOf(num)).toString();
									System.out.println(new_value);
									// 拼接字符串
									String new_st = new_op + ">" + new_value;
									System.out.println(new_st);
									// 添加到list中
									new_where.add(new_st);
								} catch (NoSuchAlgorithmException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						} else {
							// 左值不包含.，如sid>1获取sid=1
							String table = tableName;
							String column = left;
							String new_table_name = table;
							String new_field_name;
							try {
								new_field_name = KeyManager.getAESHexField(table, column) + "oOrd";
								String new_op = new_table_name + "." + new_field_name;
								System.out.println(new_op);
								// 加密s.sid>2中的2
								String num = right;
								String key = KeyManager.keysGet(table, column, new_field_name,
										KeyManager.FieldType.int_Ord);
								if (key.equals("")) {
									return "";
								}
								String[] tmpkey = key.split(",");
								int a = Integer.valueOf(tmpkey[0]);
								int b = Integer.valueOf(tmpkey[1]);
								OPEUtil o = new OPEUtil(a, b);
								String new_value = o.encrypt(Integer.valueOf(num)).toString();
								System.out.println(new_value);
								// 拼接字符串
								String new_st = new_op + ">" + new_value;
								System.out.println(new_st);
								// 添加到list中
								new_where.add(new_st);
							} catch (NoSuchAlgorithmException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						System.out.println(left + " " + right);
					} else if (operation.contains("like")) {

					}
				}
				// 拼接new sql
				String items = "";
				for (String s1 : sel_items) {
					items += s1;
					items += ",";
				}
				String joins = "";
				for (String s2 : join) {
					joins += s2;
					joins += ",";
				}
				String where = "";
				for (String s3 : new_where) {
					where += s3;
					where += " and ";
				}
				String new_st = "select " + items.substring(0, items.length() - 1) + " from "
						+ joins.substring(0, joins.length() - 1) + " where " + where.substring(0, where.length() - 5);
				System.out.println(new_st);
				return new_st;
			}
			// 拼接new sql
			String items = "";
			for (String s1 : sel_items) {
				items += s1;
				items += ",";
			}
			String joins = "";
			for (String s2 : join) {
				joins += s2;
				joins += ",";
			}
			String new_st = "select " + items.substring(0, items.length() - 1) + " from "
					+ joins.substring(0, joins.length() - 1) ;
			System.out.println(new_st);
			return new_st;
		} else if (s instanceof WithItem) {
			System.out.println(statement.toString());
		}
		return "";
	}

	static public String visit(Update statement) {
		System.out.println("Update");
		return "Update";
	}

	static public String visit(Delete statement) {
		System.out.println("Delete");
		return "Delete";
	}

	static public String visit(Replace statement) {
		System.out.println("Replace");
		return "Replace";
	}

	static public String visit(CreateTable statement) {
		System.out.println("CreateTable=" + statement.toString());
		// crypt statement
		CreateTable new_statement = new CreateTable();
		// get column
		List<ColumnDefinition> l = statement.getColumnDefinitions();
		// get table name
		Table table = statement.getTable();
		String tableName = table.getName();
		new_statement.setTable(new Table(tableName));
		// new list,for all colunms
		List<ColumnDefinition> new_l = new ArrayList<ColumnDefinition>();
		for (ColumnDefinition tmp : l) {
			if (tmp.getColDataType().getDataType().equals("int")) {
				String columnName = tmp.getColumnName();
				// 获取"sid"对应的"XXX"_Eq
				String cipher_columnName = "XXX";
				try {
					cipher_columnName = KeyManager.getAESHexField(table.getName(), columnName);
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				// rewrite int_field to 3 fields
				// 1Eq
				ColumnDefinition cd_Eq = new ColumnDefinition();
				ColDataType _cdt1 = new ColDataType();
				_cdt1.setDataType("varbinary");// _cdt1.setDataType("BIGINT");
				List<String> l1_dt = new ArrayList<String>();
				l1_dt.add("64");
				_cdt1.setArgumentsStringList(l1_dt);
				cd_Eq.setColDataType(_cdt1);
				// cd_Eq.setColumnName("IIIIIII" + "oEq");
				String Eq_tmpfield = cipher_columnName + "oEq";
				cd_Eq.setColumnName(Eq_tmpfield);
				// 在索引map<TableColumnField,String>里注册该列，并初始化key
				KeyManager.keysInit(tableName, columnName, Eq_tmpfield, KeyManager.FieldType.int_Eq);
				// over
				List<String> l1 = new ArrayList<String>();
				l1.add("NOT");
				l1.add("NULL");
				cd_Eq.setColumnSpecStrings(l1);
				new_l.add(cd_Eq);
				// 2Ord
				ColumnDefinition cd_Ord = new ColumnDefinition();
				ColDataType _cdt2 = new ColDataType();
				_cdt2.setDataType("BIGINT");
				cd_Ord.setColDataType(_cdt2);
				String Ord_tmpfield = cipher_columnName + "oOrd";
				cd_Ord.setColumnName(Ord_tmpfield);
				// 在索引map<TableColumnField,String>里注册该列，并初始化key
				KeyManager.keysInit(tableName, columnName, Ord_tmpfield, KeyManager.FieldType.int_Ord);
				// over
				List<String> l2 = new ArrayList<String>();
				l2.add("NOT");
				l2.add("NULL");
				cd_Ord.setColumnSpecStrings(l2);
				new_l.add(cd_Ord);
				// 3Hom
				ColumnDefinition cd_Add = new ColumnDefinition();
				ColDataType _cdt3 = new ColDataType();
				_cdt3.setDataType("varchar");
				List<String> l3_dt = new ArrayList<String>();
				l3_dt.add("512");
				_cdt3.setArgumentsStringList(l3_dt);
				cd_Add.setColDataType(_cdt3);
				String Add_tmpfield = cipher_columnName + "oAdd";
				cd_Add.setColumnName(Add_tmpfield);
				// 在索引map<TableColumnField,String>里注册该列，并初始化key
				KeyManager.keysInit(tableName, columnName, Add_tmpfield, KeyManager.FieldType.int_Add);
				// over
				List<String> l3 = new ArrayList<String>();
				l3.add("NOT");
				l3.add("NULL");
				cd_Add.setColumnSpecStrings(l3);
				new_l.add(cd_Add);
				// 4salt,for RND
				ColumnDefinition cd_Salt = new ColumnDefinition();
				ColDataType _cdt4 = new ColDataType();
				_cdt4.setDataType("BIGINT");
				List<String> l4_dt = new ArrayList<String>();
				l4_dt.add("8");
				_cdt4.setArgumentsStringList(l4_dt);
				cd_Salt.setColDataType(_cdt4);
				cd_Salt.setColumnName(cipher_columnName + "oSalt");
				List<String> l4 = new ArrayList<String>();
				l4.add("NOT");
				l4.add("NULL");
				cd_Salt.setColumnSpecStrings(l4);
				new_l.add(cd_Salt);
				// FILL new STATEMENT
				// new_statement.setColumnDefinitions(new_l);
				// System.out.println(new_statement.toString());
			} else if (tmp.getColDataType().getDataType().equals("varchar")
					| tmp.getColDataType().getDataType().equals("char")) {
				String columnName = tmp.getColumnName();
				// 获取"sname"对应的"XXX"_Eq
				String cipher_columnName = "XXX";
				try {
					cipher_columnName = KeyManager.getAESHexField(table.getName(), columnName);
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				// rewrite varchar_field to 3 fields
				// 1Eq
				ColumnDefinition cd_Eq = new ColumnDefinition();
				ColDataType _cdt1 = new ColDataType();
				_cdt1.setDataType("varbinary");
				List<String> l1_dt = new ArrayList<String>();
				l1_dt.add("64");
				_cdt1.setArgumentsStringList(l1_dt);
				cd_Eq.setColDataType(_cdt1);
				String Eq_tmpfield = cipher_columnName + "oEq";
				cd_Eq.setColumnName(Eq_tmpfield);
				// 在索引map<TableColumnField,String>里注册该列，并初始化key
				KeyManager.keysInit(tableName, columnName, Eq_tmpfield, KeyManager.FieldType.char_Eq);
				// over
				List<String> l1 = new ArrayList<String>();
				l1.add("NOT");
				l1.add("NULL");
				cd_Eq.setColumnSpecStrings(l1);
				new_l.add(cd_Eq);
				// // 2Ord
				// ColumnDefinition cd_Ord = new ColumnDefinition();
				// ColDataType _cdt2 = new ColDataType();
				// _cdt2.setDataType("BIGINT");
				// cd_Ord.setColDataType(_cdt2);
				// cd_Ord.setColumnName(cipher_columnName + "oOrd");
				// List<String> l2 = new ArrayList<String>();
				// l2.add("NOT");
				// l2.add("NULL");
				// cd_Ord.setColumnSpecStrings(l2);
				// new_l.add(cd_Ord);
				// search can be execute in 1eq
				// // 3Search
				// ColumnDefinition cd_Srch = new ColumnDefinition();
				// ColDataType _cdt3 = new ColDataType();
				// _cdt3.setDataType("varbinary");
				// List<String> l3_dt = new ArrayList<String>();
				// l3_dt.add("256");
				// _cdt3.setArgumentsStringList(l3_dt);
				// cd_Srch.setColDataType(_cdt3);
				// cd_Srch.setColumnName("CCCCCCCC" + "oSrch");
				// List<String> l3 = new ArrayList<String>();
				// l3.add("NOT");
				// l3.add("NULL");
				// cd_Srch.setColumnSpecStrings(l3);
				// new_l.add(cd_Srch);
				// 4salt,for RND
				ColumnDefinition cd_Salt = new ColumnDefinition();
				ColDataType _cdt4 = new ColDataType();
				_cdt4.setDataType("BIGINT");
				List<String> l4_dt = new ArrayList<String>();
				l4_dt.add("8");
				_cdt4.setArgumentsStringList(l4_dt);
				cd_Salt.setColDataType(_cdt4);
				cd_Salt.setColumnName(cipher_columnName + "oSalt");
				List<String> l4 = new ArrayList<String>();
				l4.add("NOT");
				l4.add("NULL");
				cd_Salt.setColumnSpecStrings(l4);
				new_l.add(cd_Salt);
				// FILL new STATEMENT
				// new_statement.setColumnDefinitions(new_l);
				// System.out.println(new_statement.toString());
			}
		}
		// FILL new STATEMENT
		new_statement.setColumnDefinitions(new_l);
		System.out.println(new_statement.toString());
		return new_statement.toString();
	}

	static public String visit(Drop statement) {
		System.out.println("Drop");
		return "Drop";
	}

	static public String Parser_Main(String sql) {
		try {
			Statement stmt = CCJSqlParserUtil.parse(sql);
			if (stmt instanceof CreateTable) {
				return visit((CreateTable) stmt);
			} else if (stmt instanceof Insert) {
				return visit((Insert) stmt);
			} else if (stmt instanceof Select) {
				return visit((Select) stmt);
			} else if (stmt instanceof Update) {
				return visit((Update) stmt);
			} else if (stmt instanceof Delete) {
				return visit((Delete) stmt);
			} else if (stmt instanceof Replace) {
				return visit((Replace) stmt);
			} else if (stmt instanceof Drop) {
				return visit((Drop) stmt);
			}
			return "";
		} catch (JSQLParserException e) {
			e.printStackTrace();
		}
		return "";
	}

	public static void main(String[] args) {
		// test1 create
		try {
			// SELECT * FROM tab1;
			Statement stmt = CCJSqlParserUtil
					.parse("create table student(sid int not null,sname varchar(20) not null);");
			// Statement stmt = CCJSqlParserUtil.parse("insert into
			// student(sid,sname) values(1,'Alice');");
			// Statement stmt = CCJSqlParserUtil.parse("select a from b where
			// a.id =1 and a.tid>1;");
			System.out.println(stmt.toString());
			if (stmt instanceof CreateTable) {
				visit((CreateTable) stmt);
			} else if (stmt instanceof Insert) {
				visit((Insert) stmt);
			} else if (stmt instanceof Select) {
				visit((Select) stmt);
			} else if (stmt instanceof Update) {
				visit((Update) stmt);
			} else if (stmt instanceof Delete) {
				visit((Delete) stmt);
			} else if (stmt instanceof Replace) {
				visit((Replace) stmt);
			} else if (stmt instanceof Drop) {
				visit((Drop) stmt);
			} else {

			}

		} catch (JSQLParserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// test2 insert
		try {
			Statement stmt = CCJSqlParserUtil.parse("insert into student(sid,sname) values(1,'Alice');");
			System.out.println(stmt.toString());
			visit((Insert) stmt);
			Statement stmt2 = CCJSqlParserUtil.parse("insert into student(sid,sname) values(2,'Bob');");
			System.out.println(stmt2.toString());
			visit((Insert) stmt2);
			Statement stmt3 = CCJSqlParserUtil.parse("insert into student(sid,sname) values(3,'Alice');");
			System.out.println(stmt3.toString());
			visit((Insert) stmt3);

		} catch (JSQLParserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// test3 select
		try {
			// Statement stmt = CCJSqlParserUtil.parse(
			// "select s.id,s.sname,t.tname from s,t,f,g,h,j where s.id > 2 and
			// s.id = t.id and t.tname='Bob' and s.sname = 'Alice';");
			Statement stmt = CCJSqlParserUtil.parse(
					"select student.sid,student.sname from student");
			System.out.println(stmt.toString());
			visit((Select) stmt);

		} catch (JSQLParserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println("Keymanager columns");
		for (TableColumn s : KeyManager.columns.keySet()) {
			System.out.println(s.toString() + " : " + KeyManager.columns.get(s));
		}

		System.out.println("Keymanager onioncolumns");
		for (TableColumnField s : KeyManager.onioncolumns.keySet()) {
			System.out.println(s.toString() + " : " + KeyManager.onioncolumns.get(s));
		}

	}
}
