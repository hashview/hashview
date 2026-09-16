"""Raw SQL must not name an identifier MySQL reserves.

Production runs MySQL. The unit suite runs SQLite and the parity job runs
MariaDB, and neither reserves the same words -- so a raw-SQL alias that MySQL
refuses outright is invisible to every gate in CI. That is not hypothetical:
`SELECT COUNT(*) AS groups` in dedupe.duplicate_summary parsed fine on both CI
databases and was a 1064 syntax error on every MySQL 8 install, which took out
the duplicate-hash repair script *and* silently hid the whole repair section of
Settings -> Data management (the page fell back to a count of zero, which
renders exactly like a clean table). GROUPS became reserved in MySQL 8.0.2 as
the window-function frame unit.

This scans the raw SQL the app actually builds and fails on an unquoted
identifier that collides with the reserved list, so the next one is caught on a
laptop instead of on an operator's server.
"""

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", "venv", "node_modules", "__pycache__", "migrations"}

# MySQL 8.0's own list, read from INFORMATION_SCHEMA.KEYWORDS WHERE RESERVED = 1
# on 8.0.46. Embedded rather than queried so this test needs no database.
MYSQL_RESERVED = {
    "ACCESSIBLE", "ADD", "ALL", "ALTER", "ANALYZE", "AND", "AS", "ASC", "ASENSITIVE",
    "BEFORE", "BETWEEN", "BIGINT", "BINARY", "BLOB", "BOTH", "BY", "CALL", "CASCADE",
    "CASE", "CHANGE", "CHAR", "CHARACTER", "CHECK", "COLLATE", "COLUMN", "CONDITION",
    "CONSTRAINT", "CONTINUE", "CONVERT", "CREATE", "CROSS", "CUBE", "CUME_DIST",
    "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP", "CURRENT_USER", "CURSOR",
    "DATABASE", "DATABASES", "DAY_HOUR", "DAY_MICROSECOND", "DAY_MINUTE", "DAY_SECOND",
    "DEC", "DECIMAL", "DECLARE", "DEFAULT", "DELAYED", "DELETE", "DENSE_RANK", "DESC",
    "DESCRIBE", "DETERMINISTIC", "DISTINCT", "DISTINCTROW", "DIV", "DOUBLE", "DROP", "DUAL",
    "EACH", "ELSE", "ELSEIF", "EMPTY", "ENCLOSED", "ESCAPED", "EXCEPT", "EXISTS", "EXIT",
    "EXPLAIN", "FALSE", "FETCH", "FIRST_VALUE", "FLOAT", "FLOAT4", "FLOAT8", "FOR", "FORCE",
    "FOREIGN", "FROM", "FULLTEXT", "FUNCTION", "GENERATED", "GET", "GRANT", "GROUP",
    "GROUPING", "GROUPS", "HAVING", "HIGH_PRIORITY", "HOUR_MICROSECOND", "HOUR_MINUTE",
    "HOUR_SECOND", "IF", "IGNORE", "IN", "INDEX", "INFILE", "INNER", "INOUT", "INSENSITIVE",
    "INSERT", "INT", "INT1", "INT2", "INT3", "INT4", "INT8", "INTEGER", "INTERSECT",
    "INTERVAL", "INTO", "IO_AFTER_GTIDS", "IO_BEFORE_GTIDS", "IS", "ITERATE", "JOIN",
    "JSON_TABLE", "KEY", "KEYS", "KILL", "LAG", "LAST_VALUE", "LATERAL", "LEAD", "LEADING",
    "LEAVE", "LEFT", "LIKE", "LIMIT", "LINEAR", "LINES", "LOAD", "LOCALTIME",
    "LOCALTIMESTAMP", "LOCK", "LONG", "LONGBLOB", "LONGTEXT", "LOOP", "LOW_PRIORITY",
    "MASTER_BIND", "MASTER_SSL_VERIFY_SERVER_CERT", "MATCH", "MAXVALUE", "MEDIUMBLOB",
    "MEDIUMINT", "MEDIUMTEXT", "MIDDLEINT", "MINUTE_MICROSECOND", "MINUTE_SECOND", "MOD",
    "MODIFIES", "NATURAL", "NO_WRITE_TO_BINLOG", "NOT", "NTH_VALUE", "NTILE", "NULL",
    "NUMERIC", "OF", "ON", "OPTIMIZE", "OPTIMIZER_COSTS", "OPTION", "OPTIONALLY", "OR",
    "ORDER", "OUT", "OUTER", "OUTFILE", "OVER", "PARTITION", "PERCENT_RANK", "PRECISION",
    "PRIMARY", "PROCEDURE", "PURGE", "RANGE", "RANK", "READ", "READ_WRITE", "READS", "REAL",
    "RECURSIVE", "REFERENCES", "REGEXP", "RELEASE", "RENAME", "REPEAT", "REPLACE",
    "REQUIRE", "RESIGNAL", "RESTRICT", "RETURN", "REVOKE", "RIGHT", "RLIKE", "ROW",
    "ROW_NUMBER", "ROWS", "SCHEMA", "SCHEMAS", "SECOND_MICROSECOND", "SELECT", "SENSITIVE",
    "SEPARATOR", "SET", "SHOW", "SIGNAL", "SMALLINT", "SPATIAL", "SPECIFIC", "SQL",
    "SQL_BIG_RESULT", "SQL_CALC_FOUND_ROWS", "SQL_SMALL_RESULT", "SQLEXCEPTION", "SQLSTATE",
    "SQLWARNING", "SSL", "STARTING", "STORED", "STRAIGHT_JOIN", "SYSTEM", "TABLE",
    "TERMINATED", "THEN", "TINYBLOB", "TINYINT", "TINYTEXT", "TO", "TRAILING", "TRIGGER",
    "TRUE", "UNDO", "UNION", "UNIQUE", "UNLOCK", "UNSIGNED", "UPDATE", "USAGE", "USE",
    "USING", "UTC_DATE", "UTC_TIME", "UTC_TIMESTAMP", "VALUES", "VARBINARY", "VARCHAR",
    "VARCHARACTER", "VARYING", "VIRTUAL", "WHEN", "WHERE", "WHILE", "WINDOW", "WITH",
    "WRITE", "XOR", "YEAR_MONTH", "ZEROFILL"}

# An alias or identifier we introduce, unless it is already backtick-quoted.
_ALIAS = re.compile(r"\bAS\s+(?!`)([A-Za-z_][A-Za-z0-9_]*)", re.I)

# A real SQL fragment starts with a SQL verb or a clause keyword. Prose that
# merely contains the word "select" does not, which keeps docstrings out.
_SQL_START = re.compile(
    r"^\s*\(?\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WITH|FROM|JOIN"
    r"|LEFT|INNER|GROUP|ORDER|HAVING|WHERE|UNION|SET|VALUES)\b",
    re.I,
)


def _docstrings(tree):
    """Every docstring in a module, so prose is never mistaken for SQL."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            text = ast.get_docstring(node, clean=False)
            if text is not None:
                found.add(text)
    return found


def _sql_string_literals():
    """(path, line, string) for every literal that looks like SQL."""
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if SKIP_DIRS & set(path.parts):
            continue
        try:
            tree = ast.parse(path.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        docs = _docstrings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if node.value in docs or not _SQL_START.match(node.value):
                continue
            yield path.relative_to(REPO_ROOT), node.lineno, node.value


def test_no_raw_sql_alias_collides_with_a_mysql_reserved_word():
    offenders = []
    for path, line, sql in _sql_string_literals():
        for match in _ALIAS.finditer(sql):
            name = match.group(1)
            if name.upper() in MYSQL_RESERVED:
                offenders.append(f"{path}:{line}  AS {name}  -- in: {sql.strip()[:80]}")
    assert not offenders, (
        "Raw SQL names an identifier MySQL reserves; it will be a 1064 syntax error "
        "on production MySQL even though SQLite and MariaDB accept it.\n  "
        + "\n  ".join(offenders)
        + "\nRename the alias (preferred -- backticks are not portable to SQLite)."
    )


def test_the_detector_finds_a_planted_collision():
    """The scanner above is only worth having if it actually fires.

    Assembled rather than written as one literal so this file stays inside the
    scan above -- spelling it out whole would make the guard flag its own
    fixture, and excluding this file to silence that would leave a blind spot
    exactly where the detector lives.
    """
    planted = "SELECT COUNT(*) AS " + "groups" + " FROM (SELECT 1 AS cnt) AS g"
    hits = [m.group(1) for m in _ALIAS.finditer(planted)
            if m.group(1).upper() in MYSQL_RESERVED]
    assert hits == ["groups"]


def test_the_detector_ignores_prose_and_quoted_identifiers():
    """Guards against the opposite failure: a scanner that flags everything."""
    prose = "Records the line count with the SAME semantics as before, so nothing drifts"
    assert not _SQL_START.match(prose)
    quoted = "SELECT COUNT(*) AS " + "`groups`" + " FROM t"
    assert not [m for m in _ALIAS.finditer(quoted) if m.group(1).upper() in MYSQL_RESERVED]


def test_the_scan_actually_reaches_the_apps_sql():
    """A scanner that silently matched nothing would pass forever."""
    scanned = {str(path) for path, _, _ in _sql_string_literals()}
    assert "hashview/utils/dedupe.py" in scanned
