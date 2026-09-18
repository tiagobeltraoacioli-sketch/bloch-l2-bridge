"""Structured SQLite schema checks for private bridge observation stores."""

import re


COLLATION_CLAUSE = re.compile(r'(?i)(?<![A-Za-z0-9_])COLLATE(?![A-Za-z0-9_])')


def validate_schema(db, require, specifications):
    """Refuse views, weakened keys/collations and trigger-bearing store tables."""
    for table, (expected_columns, expected_unique) in specifications.items():
        objects = db.execute('''SELECT type FROM sqlite_schema
            WHERE name=? AND type IN ('table','view')''', (table,)).fetchall()
        require(objects == [('table',)], 'invalid SQLite store table')

        # table_info omits declared collations. A recreated status/facts column
        # with NOCASE would otherwise retain the expected type and constraints,
        # while changing equality predicates. Store DDL is small and generated
        # by this project, so reject every explicit collation clause. Identity
        # index metadata below independently proves the effective key collation.
        ddl_count = db.execute('''SELECT COUNT(*) FROM sqlite_schema
            WHERE type='table' AND name=?''', (table,)).fetchone()[0]
        ddl = db.execute('''SELECT sql FROM sqlite_schema WHERE type='table' AND name=?
            AND typeof(sql)='text' AND length(CAST(sql AS BLOB))<=4096''', (table,)).fetchone()
        require(ddl_count == 1 and ddl is not None and not COLLATION_CLAUSE.search(ddl[0]),
                'invalid SQLite store collation')

        column_count = db.execute('SELECT COUNT(*) FROM pragma_table_info(?)', (table,)).fetchone()[0]
        require(column_count == len(expected_columns), 'invalid SQLite store columns')
        columns = db.execute('''SELECT cid,name,type,"notnull",dflt_value,pk
            FROM pragma_table_info(?) WHERE typeof(name)='text'
            AND length(CAST(name AS BLOB))<=64 AND typeof(type)='text'
            AND length(CAST(type AS BLOB))<=32 ORDER BY cid''', (table,)).fetchall()
        require(len(columns) == column_count and tuple(columns) == expected_columns,
                'invalid SQLite store columns')

        index_count = db.execute('SELECT COUNT(*) FROM pragma_index_list(?)', (table,)).fetchone()[0]
        # Every expected key has one SQLite auto-index in these rowid tables.
        # Refuse injected secondary indexes as well as bounding metadata before
        # it is copied into Python.
        require(index_count == len(expected_unique), 'invalid SQLite store indexes')
        indexes = db.execute('''SELECT name,"unique",origin,partial FROM pragma_index_list(?)
            WHERE typeof(name)='text' AND length(CAST(name AS BLOB))<=128
            AND typeof(origin)='text' AND length(CAST(origin AS BLOB))<=8''', (table,)).fetchall()
        require(index_count == len(indexes), 'invalid SQLite store indexes')
        unique = set()
        for name, is_unique, origin, partial in indexes:
            if not is_unique:
                continue
            require(origin in ('pk', 'u') and partial == 0, 'invalid SQLite unique index')
            item_count = db.execute('SELECT COUNT(*) FROM pragma_index_xinfo(?)', (name,)).fetchone()[0]
            require(1 <= item_count <= max(map(len, expected_unique)) + 1,
                    'invalid SQLite index fields')
            items = db.execute('''SELECT seqno,cid,name,desc,coll,key FROM pragma_index_xinfo(?)
                WHERE (name IS NULL OR (typeof(name)='text' AND length(CAST(name AS BLOB))<=64))
                AND (coll IS NULL OR (typeof(coll)='text' AND length(CAST(coll AS BLOB))<=16))
                ORDER BY seqno''', (name,)).fetchall()
            require(item_count == len(items), 'invalid SQLite index fields')
            keys = []
            for _, cid, column, descending, collation, key in items:
                if key:
                    require(cid >= 0 and type(column) is str and descending == 0
                            and collation == 'BINARY', 'invalid SQLite identity collation')
                    keys.append(column)
            unique.add(tuple(keys))
        require(unique == expected_unique, 'invalid SQLite identity constraints')

        triggers = db.execute('''SELECT COUNT(*) FROM sqlite_schema
            WHERE type='trigger' AND tbl_name=?''', (table,)).fetchone()[0]
        require(triggers == 0, 'SQLite store triggers are not allowed')
