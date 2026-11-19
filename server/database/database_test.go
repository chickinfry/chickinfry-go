package database

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/chickinfry/chickinfry-go/server/host"
	"github.com/chickinfry/chickinfry-go/server/internal/authhook"
)

func TestTransactionLifetimeAndUnknownCommit(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		operations := []string{}
		connection := New(1)
		connection.call = func(_ string, input any) ([]byte, error) {
			data, _ := json.Marshal(input)
			var frame struct {
				RID   int64
				Op    string
				Lease int64
			}
			_ = json.Unmarshal(data, &frame)
			if frame.RID != 1 || frame.Op != "begin" && frame.Lease != 7 {
				t.Fatal("request/lease lost")
			}
			operations = append(operations, frame.Op)
			switch frame.Op {
			case "begin":
				return []byte(`{"lease":7}`), nil
			case "exec":
				return []byte(`{"rows":[]}`), nil
			case "commit":
				if unknown {
					return []byte(`{"error":"commit_unknown"}`), nil
				}
			}
			return []byte(`{}`), nil
		}
		var saved *Connection
		err := connection.Transaction(func(tx *Connection) error {
			saved = tx
			if tx.Transaction(func(*Connection) error { return nil }) == nil {
				t.Fatal("nested transaction accepted")
			}
			_, err := tx.Query("generated", nil)
			return err
		})
		if unknown {
			failure, ok := errors.AsType[*host.Error](err)
			if !ok || failure.Code != "commit_unknown" {
				t.Fatalf("lost commit uncertainty: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(operations, []string{"begin", "exec", "commit"}) {
			t.Fatalf("unexpected retry/rollback: %v", operations)
		}
		if _, err := saved.Query("generated", nil); err == nil {
			t.Fatal("ended lease reused")
		}
		connection.Close()
		if _, err := connection.Query("generated", nil); err == nil {
			t.Fatal("closed request reused")
		}
	}
}

func TestCallbackFailureRollsBack(t *testing.T) {
	operations := []string{}
	connection := New(2)
	connection.call = func(_ string, input any) ([]byte, error) {
		data, _ := json.Marshal(input)
		var frame struct{ Op string }
		_ = json.Unmarshal(data, &frame)
		operations = append(operations, frame.Op)
		if frame.Op == "begin" {
			return []byte(`{"lease":8}`), nil
		}
		return []byte(`{}`), nil
	}
	failure := errors.New("business failure")
	if !errors.Is(connection.Transaction(func(*Connection) error { return failure }), failure) {
		t.Fatal("business failure lost")
	}
	if !reflect.DeepEqual(operations, []string{"begin", "rollback"}) {
		t.Fatalf("operations: %v", operations)
	}
}

func TestAuthHookTransactionOnlyExecutesAndRevokesCopies(t *testing.T) {
	callbackFailure := errors.New("creating hook failed")
	var saved, copied *Connection
	var operations []string
	err := WithAuthHookTransaction(authhook.NewTransaction(41, 93), func(connection *Connection) error {
		connection.call = func(port string, input any) ([]byte, error) {
			frame, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if port != "db" || string(frame) != `{"rid":41,"op":"exec","lease":93,"sql":"generated","params":[]}` {
				t.Fatalf("unexpected auth transaction host call: %s %s", port, frame)
			}
			operations = append(operations, port)
			return []byte(`{"rows":[]}`), nil
		}
		if err := connection.Transaction(func(*Connection) error { t.Fatal("nested transaction called"); return nil }); err == nil {
			t.Fatal("borrowed connection accepted a nested transaction")
		}
		if _, err := connection.Query("generated", nil); err != nil {
			t.Fatal(err)
		}
		copy := *connection
		saved, copied = connection, &copy
		*connection = Connection{}
		return callbackFailure
	})
	if !errors.Is(err, callbackFailure) {
		t.Fatalf("callback error=%v", err)
	}
	for _, connection := range []*Connection{saved, copied} {
		if _, err := connection.Query("generated", nil); err == nil {
			t.Fatal("closed auth transaction accepted a query")
		}
	}
	if len(operations) != 1 {
		t.Fatalf("closing a borrowed callback touched the host: %v", operations)
	}
}
