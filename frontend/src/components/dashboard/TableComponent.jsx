const TableComponent = ({
  columns,
  rows,
  rowKey,
  emptyText = "No records available.",
  rowClassName,
}) => {
  const resolvedRowKey = rowKey || ((row, index) => row.id || index);

  return (
    <div className="tl-soc-table">
      {rows.length > 0 ? (
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>{column.title}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr
                key={resolvedRowKey(row, index)}
                className={typeof rowClassName === "function" ? rowClassName(row, index) : rowClassName || ""}
              >
                {columns.map((column) => (
                  <td key={column.key}>
                    {column.render ? column.render(row[column.key], row, index) : row[column.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="tl-soc-empty">{emptyText}</div>
      )}
    </div>
  );
};

export default TableComponent;
