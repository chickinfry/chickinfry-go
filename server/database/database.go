// Package database owns request and transaction host transport for generated ORM.
package database

import (
	"encoding/json"
	"errors"

	"github.com/chickinfry/chickinfry-go/server/host"
)

// Connection retains the request and transaction lifetime.
type Connection struct {
	rid    int64
	lease  int64
	ended  bool
	parent *Connection
	call   func(string, any) ([]byte, error)
}

// New binds a generated database to one active request.
func New(rid int64) *Connection { return &Connection{rid: rid, call: host.Call} }

func (connection *Connection) active() error {
	if connection.rid < 1 || connection.rid > host.MaxHandle || connection.ended || connection.parent != nil && connection.parent.ended {
		return errors.New("database connection is inactive")
	}
	return nil
}

// Query executes generated SQL with positional parameters on the bound connection.
func (connection *Connection) Query(sql string, params []any) ([]json.RawMessage, error) {
	if err := connection.active(); err != nil {
		return nil, err
	}
	if params == nil {
		params = []any{}
	}
	var frame []byte
	var err error
	if connection.lease == 0 {
		frame, err = connection.call("db", struct {
			RID    int64  `json:"rid"`
			Op     string `json:"op"`
			SQL    string `json:"sql"`
			Params []any  `json:"params"`
		}{connection.rid, "query", sql, params})
	} else {
		frame, err = connection.call("db", struct {
			RID    int64  `json:"rid"`
			Op     string `json:"op"`
			Lease  int64  `json:"lease"`
			SQL    string `json:"sql"`
			Params []any  `json:"params"`
		}{connection.rid, "exec", connection.lease, sql, params})
	}
	if err != nil {
		return nil, err
	}
	var rows []json.RawMessage
	if err := host.Envelope(frame, "rows", &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, errors.New("database rows must be an array")
	}
	return rows, nil
}

// Transaction runs the callback on the same lease and never retries a commit.
func (connection *Connection) Transaction(run func(*Connection) error) (err error) {
	if err := connection.active(); err != nil {
		return err
	}
	if connection.lease != 0 {
		return errors.New("nested transactions are unsupported")
	}
	frame, err := connection.call("db", struct {
		RID int64  `json:"rid"`
		Op  string `json:"op"`
	}{connection.rid, "begin"})
	if err != nil {
		return err
	}
	var lease int64
	if err := host.Envelope(frame, "lease", &lease); err != nil {
		return err
	}
	if lease < 1 || lease > host.MaxHandle {
		return errors.New("invalid transaction lease")
	}
	transaction := &Connection{rid: connection.rid, lease: lease, parent: connection, call: connection.call}
	defer func() {
		if !transaction.ended {
			err = errors.Join(err, transaction.finish("rollback"))
		}
	}()
	if err = run(transaction); err != nil {
		return err
	}
	return transaction.finish("commit")
}

func (connection *Connection) finish(operation string) error {
	connection.ended = true
	frame, err := connection.call("db", struct {
		RID   int64  `json:"rid"`
		Op    string `json:"op"`
		Lease int64  `json:"lease"`
	}{connection.rid, operation, connection.lease})
	if err != nil {
		return err
	}
	return host.Envelope(frame, "", nil)
}

// Close prevents the generated ORM from starting new calls after request completion.
// The host owns cancellation and actual PostgreSQL connection cleanup.
func (connection *Connection) Close() { connection.ended = true }
