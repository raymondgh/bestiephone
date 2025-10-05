package sqlitedrv

// #cgo CFLAGS: -DSQLITE_THREADSAFE=1
// #cgo LDFLAGS: -lsqlite3
// #include <sqlite3.h>
// #include <stdlib.h>
// static int bind_text(sqlite3_stmt* stmt, int idx, const char* value, int len) {
//   return sqlite3_bind_text(stmt, idx, value, len, SQLITE_TRANSIENT);
// }
// static int bind_blob(sqlite3_stmt* stmt, int idx, const void* value, int len) {
//   return sqlite3_bind_blob(stmt, idx, value, len, SQLITE_TRANSIENT);
// }
import "C"

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"time"
	"unsafe"
)

func init() {
	sql.Register("custom_sqlite", &Driver{})
}

type Driver struct{}

type conn struct {
	db *C.sqlite3
}

type stmt struct {
	conn  *conn
	query string
}

type rows struct {
	stmt    *C.sqlite3_stmt
	conn    *conn
	columns []string
	closed  bool
}

type tx struct {
	conn *conn
}

func (d *Driver) Open(name string) (driver.Conn, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var db *C.sqlite3
	if rc := C.sqlite3_open_v2(cname, &db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil); rc != C.SQLITE_OK {
		msg := C.GoString(C.sqlite3_errmsg(db))
		if db != nil {
			C.sqlite3_close(db)
		}
		return nil, fmt.Errorf("sqlite open: %s", msg)
	}
	C.sqlite3_busy_timeout(db, 5000)
	c := &conn{db: db}
	if err := c.execSimple("PRAGMA foreign_keys=ON"); err != nil {
		c.Close()
		return nil, err
	}
	if err := c.execSimple("PRAGMA journal_mode=WAL"); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *conn) execSimple(sql string) error {
	csql := C.CString(sql)
	defer C.free(unsafe.Pointer(csql))
	if rc := C.sqlite3_exec(c.db, csql, nil, nil, nil); rc != C.SQLITE_OK {
		return errors.New(C.GoString(C.sqlite3_errmsg(c.db)))
	}
	return nil
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return &stmt{conn: c, query: query}, nil
}

func (c *conn) Close() error {
	if c.db != nil {
		if rc := C.sqlite3_close(c.db); rc != C.SQLITE_OK {
			return fmt.Errorf("sqlite close: %s", C.GoString(C.sqlite3_errmsg(c.db)))
		}
		c.db = nil
	}
	return nil
}

func (c *conn) Begin() (driver.Tx, error) {
	if err := c.execSimple("BEGIN"); err != nil {
		return nil, err
	}
	return &tx{conn: c}, nil
}

func (t *tx) Commit() error {
	return t.conn.execSimple("COMMIT")
}

func (t *tx) Rollback() error {
	return t.conn.execSimple("ROLLBACK")
}

func (s *stmt) Close() error {
	return nil
}

func (s *stmt) NumInput() int {
	return -1
}

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	cstmt, err := s.prepare()
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(cstmt)
	if err := bindArgs(cstmt, args); err != nil {
		return nil, err
	}
	rc := C.sqlite3_step(cstmt)
	if rc != C.SQLITE_DONE {
		return nil, fmt.Errorf("sqlite step: %s", C.GoString(C.sqlite3_errmsg(s.conn.db)))
	}
	lastID := int64(C.sqlite3_last_insert_rowid(s.conn.db))
	affected := int64(C.sqlite3_changes(s.conn.db))
	return &result{lastID: lastID, affected: affected}, nil
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	cstmt, err := s.prepare()
	if err != nil {
		return nil, err
	}
	if err := bindArgs(cstmt, args); err != nil {
		C.sqlite3_finalize(cstmt)
		return nil, err
	}
	colCount := int(C.sqlite3_column_count(cstmt))
	cols := make([]string, colCount)
	for i := 0; i < colCount; i++ {
		cols[i] = C.GoString(C.sqlite3_column_name(cstmt, C.int(i)))
	}
	return &rows{stmt: cstmt, conn: s.conn, columns: cols}, nil
}

func (s *stmt) prepare() (*C.sqlite3_stmt, error) {
	cquery := C.CString(s.query)
	defer C.free(unsafe.Pointer(cquery))
	var cstmt *C.sqlite3_stmt
	if rc := C.sqlite3_prepare_v2(s.conn.db, cquery, -1, &cstmt, nil); rc != C.SQLITE_OK {
		return nil, fmt.Errorf("sqlite prepare: %s", C.GoString(C.sqlite3_errmsg(s.conn.db)))
	}
	return cstmt, nil
}

type result struct {
	lastID   int64
	affected int64
}

func (r *result) LastInsertId() (int64, error) { return r.lastID, nil }

func (r *result) RowsAffected() (int64, error) { return r.affected, nil }

func bindArgs(stmt *C.sqlite3_stmt, args []driver.Value) error {
	for i, arg := range args {
		idx := C.int(i + 1)
		switch v := arg.(type) {
		case nil:
			C.sqlite3_bind_null(stmt, idx)
		case int64:
			C.sqlite3_bind_int64(stmt, idx, C.sqlite3_int64(v))
		case float64:
			C.sqlite3_bind_double(stmt, idx, C.double(v))
		case bool:
			if v {
				C.sqlite3_bind_int(stmt, idx, 1)
			} else {
				C.sqlite3_bind_int(stmt, idx, 0)
			}
		case []byte:
			if len(v) == 0 {
				C.bind_blob(stmt, idx, unsafe.Pointer(nil), 0)
			} else {
				C.bind_blob(stmt, idx, unsafe.Pointer(&v[0]), C.int(len(v)))
			}
		case string:
			cstr := C.CString(v)
			C.bind_text(stmt, idx, cstr, C.int(len(v)))
			C.free(unsafe.Pointer(cstr))
		case time.Time:
			formatted := v.UTC().Format(time.RFC3339Nano)
			cstr := C.CString(formatted)
			C.bind_text(stmt, idx, cstr, C.int(len(formatted)))
			C.free(unsafe.Pointer(cstr))
		default:
			return fmt.Errorf("unsupported bind type %T", arg)
		}
	}
	return nil
}

func (r *rows) Columns() []string {
	return r.columns
}

func (r *rows) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.stmt != nil {
		C.sqlite3_finalize(r.stmt)
		r.stmt = nil
	}
	return nil
}

func (r *rows) Next(dest []driver.Value) error {
	rc := C.sqlite3_step(r.stmt)
	switch rc {
	case C.SQLITE_ROW:
		for i := range dest {
			typeCode := C.sqlite3_column_type(r.stmt, C.int(i))
			switch typeCode {
			case C.SQLITE_INTEGER:
				dest[i] = int64(C.sqlite3_column_int64(r.stmt, C.int(i)))
			case C.SQLITE_FLOAT:
				dest[i] = float64(C.sqlite3_column_double(r.stmt, C.int(i)))
			case C.SQLITE_TEXT:
				dest[i] = C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(r.stmt, C.int(i)))))
			case C.SQLITE_BLOB:
				sz := C.sqlite3_column_bytes(r.stmt, C.int(i))
				if sz == 0 {
					dest[i] = []byte{}
				} else {
					ptr := C.sqlite3_column_blob(r.stmt, C.int(i))
					buf := C.GoBytes(ptr, sz)
					dest[i] = buf
				}
			case C.SQLITE_NULL:
				dest[i] = nil
			default:
				dest[i] = nil
			}
		}
		return nil
	case C.SQLITE_DONE:
		r.Close()
		return io.EOF
	default:
		err := fmt.Errorf("sqlite step: %s", C.GoString(C.sqlite3_errmsg(r.conn.db)))
		r.Close()
		return err
	}
}
