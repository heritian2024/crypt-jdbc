package KeyManage;

public class TableColumnField {
	private String table;
	private String column;
	private String field;

	public TableColumnField(String t, String c, String f) {
		table = new String(t);
		column = new String(c);
		field = new String(f);
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

	public String getField() {
		return field;
	}

	public void setField(String field) {
		this.field = field;
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof TableColumnField) {
			TableColumnField t = (TableColumnField) o;
			if (this.table.equals(t.table) && this.column.equals(t.column) && this.field.equals(t.field)) {
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
		return this.table + " " + this.column + " " + this.field;
	}

	public static void main(String[] args) {
		TableColumnField t1 = new TableColumnField("student", "sid", "Eq");
		TableColumnField t2 = new TableColumnField("student", "sid", "Eq");
		boolean b = t1.equals(t2);
		System.out.println(b);
	}
}
