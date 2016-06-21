package KeyManage;

public class TableColumn {
	private String table;
	private String column;

	public TableColumn(String t, String c) {
		table = new String(t);
		column = new String(c);
	}

	public String getTable() {
		return table;
	}

	public void setTable(String table) {
		this.table = table;
	}

	public String getColumn() {
		return column;
	}

	public void setColumn(String column) {
		this.column = column;
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof TableColumn) {
			TableColumn t = (TableColumn) o;
			if (this.table.equals(t.table) && this.column.equals(t.column)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (this.table + this.column).hashCode();
	}

	@Override
	public String toString() {
		return this.table + " " + this.column;
	}

	public static void main(String[] args) {
		TableColumn t1 = new TableColumn("student", "sid");
		TableColumn t2 = new TableColumn("student", "sid");
		boolean b = t1.equals(t2);
		System.out.println(b);
	}
}
