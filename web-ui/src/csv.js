// Minimal RFC-4180 CSV parser. Handles quoted fields and CRLF/LF line endings.
// Expected header: name,url,username,password,note (case-insensitive, order-flexible).

/**
 * Parse a CSV string into an array of entry objects.
 * Returns { entries: [...], errors: [...] }.
 * Rows missing `name` are skipped with an error note.
 */
export function parseCsv(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!lines) return { entries: [], errors: ["CSV 内容为空"] };

  const rows = splitCsvRows(lines);
  if (rows.length < 2) return { entries: [], errors: ["CSV 没有数据行（只有表头或为空）"] };

  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = (name) => header.indexOf(name);

  const iName = col("name");
  const iUrl = col("url");
  const iUser = col("username") !== -1 ? col("username") : col("user");
  const iPw = col("password");
  const iNote = col("note");

  if (iName === -1) return { entries: [], errors: ['CSV 缺少必要列 "name"'] };

  const entries = [];
  const errors = [];

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    const name = get(r, iName).trim();
    if (!name) {
      errors.push(`第 ${i + 1} 行：name 为空，已跳过`);
      continue;
    }
    entries.push({
      name,
      url: get(r, iUrl),
      username: get(r, iUser),
      password: get(r, iPw),
      note: get(r, iNote),
    });
  }

  return { entries, errors };
}

function get(row, idx) {
  return idx === -1 ? "" : (row[idx] ?? "");
}

// Split CSV text into rows of fields, respecting RFC-4180 quoting.
function splitCsvRows(text) {
  const rows = [];
  let row = [];
  let i = 0;

  while (i < text.length) {
    if (text[i] === '"') {
      // Quoted field
      let field = "";
      i++; // skip opening quote
      while (i < text.length) {
        if (text[i] === '"' && text[i + 1] === '"') {
          field += '"';
          i += 2;
        } else if (text[i] === '"') {
          i++; // skip closing quote
          break;
        } else {
          field += text[i++];
        }
      }
      row.push(field);
      // skip comma or newline after closing quote
      if (text[i] === ",") i++;
      else if (text[i] === "\n") { rows.push(row); row = []; i++; }
    } else {
      // Unquoted field — read until comma or newline
      let start = i;
      while (i < text.length && text[i] !== "," && text[i] !== "\n") i++;
      row.push(text.slice(start, i));
      if (i < text.length) {
        if (text[i] === ",") i++;
        else { rows.push(row); row = []; i++; }
      }
    }
  }

  if (row.length > 0) rows.push(row);
  return rows;
}
