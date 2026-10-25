package database_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chickinfry/chickinfry-go/server/database"
	"github.com/chickinfry/chickinfry-go/server/host"
	"github.com/chickinfry/chickinfry-go/server/orm"
)

func repositoryForTest(t *testing.T, query func(string, []any) ([]json.RawMessage, error)) orm.Repository {
	t.Helper()
	connection := database.NewTestConnection(func(name string, input any) ([]byte, error) {
		frame, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			SQL    string
			Params []any
			RID    int64
			Op     string
		}
		if err := json.Unmarshal(frame, &request); err != nil {
			t.Fatal(err)
		}
		if name != "db" || request.RID != 1 || request.Op != "query" {
			t.Fatalf("unexpected host call: %s %s", name, frame)
		}
		rows, err := query(request.SQL, request.Params)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Rows []json.RawMessage `json:"rows"`
		}{rows})
	})
	return orm.Repository{Connection: connection, Table: orm.Table{Name: "items", Primary: []string{"tenant", "id"}, Columns: []orm.Column{
		{Name: "tenant", Kind: "string", Primary: true}, {Name: "id", Kind: "integer", Primary: true},
		{Name: "name", Kind: "string"}, {Name: "count", Kind: "integer", Optional: true},
		{Name: "created_at", Kind: "timestamp", Optional: true},
	}}}
}

func TestORMUpsertUsesCompleteConflictKeyAndOnlySuppliedMutableValues(t *testing.T) {
	want := json.RawMessage(`{"tenant":"t","id":1,"name":"new","count":3,"created_at":"2026-10-26T00:00:00.000Z"}`)
	calls := 0
	repository := repositoryForTest(t, func(sql string, params []any) ([]json.RawMessage, error) {
		calls++
		if !strings.Contains(sql, `on conflict ("tenant", "id") do update set "name" = excluded."name", "count" = excluded."count" returning `) || strings.Contains(sql, `"created_at" =`) {
			t.Fatalf("incorrect upsert: %s", sql)
		}
		if !reflect.DeepEqual(params, []any{"t", float64(1), "new", float64(3)}) {
			t.Fatalf("incorrect upsert values: %v", params)
		}
		return []json.RawMessage{want}, nil
	})
	row, err := repository.Upsert(map[string]any{"tenant": "t", "id": int32(1), "name": "new", "count": int32(3)})
	if err != nil || string(row) != string(want) {
		t.Fatalf("upsert result = %s, %v", row, err)
	}
	for _, values := range []map[string]any{
		{"tenant": "t", "name": "missing key"},
		{"tenant": "t", "id": int32(1)},
		{"tenant": "t", "id": int32(1), "name": "n", "unknown": "x"},
	} {
		if _, err := repository.Upsert(values); err == nil {
			t.Fatal("invalid upsert accepted")
		}
	}
	repository.Table.Columns[2].Optional = true
	if _, err := repository.Upsert(map[string]any{"tenant": "t", "id": int32(1)}); err == nil {
		t.Fatal("upsert without mutable values accepted")
	}
	if calls != 1 {
		t.Fatalf("invalid upsert reached I/O: %d", calls)
	}
}

func TestORMFindManyOrdersFilteredRowsWithBoundPagination(t *testing.T) {
	repository := repositoryForTest(t, func(sql string, params []any) ([]json.RawMessage, error) {
		if !strings.Contains(sql, `where ("count" in ($1, $2) and "name" <> $3) order by "count" desc, "id" asc limit $4 offset $5`) || !reflect.DeepEqual(params, []any{float64(1), float64(2), "excluded", float64(3), float64(4)}) {
			t.Fatalf("find many: %s %v", sql, params)
		}
		return []json.RawMessage{}, nil
	})
	rows, err := repository.FindMany(orm.FindMany{
		Where:   orm.And(orm.Field[int32]{Name: "count"}.IsIn([]int32{1, 2}), orm.Field[string]{Name: "name"}.Ne("excluded")),
		OrderBy: []orm.Order{orm.Field[int32]{Name: "count"}.Desc(), orm.Field[int32]{Name: "id"}.Asc()},
		Limit:   new(int32(3)), Offset: new(int32(4)),
	})
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty find result: %v %v", rows, err)
	}
}

func TestORMIncrementCombinesAtomicAdditionAndConditionalPatch(t *testing.T) {
	want := json.RawMessage(`{"count":4}`)
	calls := 0
	repository := repositoryForTest(t, func(sql string, params []any) ([]json.RawMessage, error) {
		calls++
		if calls == 1 {
			if !strings.Contains(sql, `set "count" = "count" + $1 where "tenant" = $2 and "id" = $3 returning `) || !reflect.DeepEqual(params, []any{float64(1), "t", float64(1)}) {
				t.Fatalf("increment: %s %v", sql, params)
			}
		} else {
			if !strings.Contains(sql, `set "count" = "count" + $1, "name" = $2 where "tenant" = $3 and "id" = $4 and ("count" < $5) returning `) || !reflect.DeepEqual(params, []any{float64(-1), "changed", "t", float64(1), float64(5)}) {
				t.Fatalf("conditional increment: %s %v", sql, params)
			}
		}
		return []json.RawMessage{want}, nil
	})
	key := map[string]any{"tenant": "t", "id": int32(1)}
	if row, err := repository.Increment(key, map[string]int32{"count": 1}); err != nil || string(row) != string(want) {
		t.Fatalf("increment = %s, %v", row, err)
	}
	if row, err := repository.IncrementIf(key, orm.Field[int32]{Name: "count"}.Lt(5), map[string]int32{"count": -1}, map[string]any{"name": "changed"}); err != nil || string(row) != string(want) {
		t.Fatalf("conditional increment = %s, %v", row, err)
	}
	for _, amounts := range []map[string]int32{nil, {}, {"count": 0}, {"id": 1}, {"name": 1}, {"unknown": 1}} {
		if _, err := repository.Increment(key, amounts); err == nil {
			t.Fatalf("invalid increment accepted: %v", amounts)
		}
	}
	for _, test := range []struct {
		condition orm.Filter
		patch     map[string]any
	}{
		{orm.Filter{}, map[string]any{"name": "n"}},
		{orm.Field[int32]{Name: "count"}.Lt(5), nil},
		{orm.Field[int32]{Name: "count"}.Lt(5), map[string]any{"count": int32(2)}},
	} {
		if _, err := repository.IncrementIf(key, test.condition, map[string]int32{"count": 1}, test.patch); err == nil {
			t.Fatal("invalid conditional increment accepted")
		}
	}
	if calls != 2 {
		t.Fatalf("invalid increment reached I/O: %d", calls)
	}
}

func TestORMConditionalMutationsPreserveNestedPredicate(t *testing.T) {
	want := json.RawMessage(`{"tenant":"t","id":1,"name":"changed","count":3,"created_at":"2026-10-26T00:00:00.000Z"}`)
	selection := ` returning "tenant", "id", "name", "count", "created_at"::text as "created_at"`
	key := map[string]any{"tenant": "t", "id": int32(1)}
	patch := map[string]any{"name": "changed"}
	count, name := orm.Field[int32]{Name: "count"}, orm.Field[string]{Name: "name"}
	condition := orm.And(count.Gte(2), orm.Or(name.Eq("old"), orm.Not(count.IsIn([]int32{8, 9}))))
	for _, test := range []struct {
		name      string
		increment bool
		sql       string
		params    []any
	}{
		{
			name:   "UpdateIf",
			sql:    `update "items" set "name" = $1 where "tenant" = $2 and "id" = $3 and (("count" >= $4 and ("name" = $5 or not ("count" in ($6, $7)))))`,
			params: []any{"changed", "t", float64(1), float64(2), "old", float64(8), float64(9)},
		},
		{
			name: "IncrementIf", increment: true,
			sql:    `update "items" set "count" = "count" + $1, "name" = $2 where "tenant" = $3 and "id" = $4 and (("count" >= $5 and ("name" = $6 or not ("count" in ($7, $8)))))`,
			params: []any{float64(1), "changed", "t", float64(1), float64(2), "old", float64(8), float64(9)},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			repository := repositoryForTest(t, func(sql string, params []any) ([]json.RawMessage, error) {
				calls++
				if sql != test.sql+selection || !reflect.DeepEqual(params, test.params) {
					t.Fatalf("conditional mutation: %s %v; want %s %v", sql, params, test.sql+selection, test.params)
				}
				return []json.RawMessage{want}, nil
			})
			var row json.RawMessage
			var err error
			if test.increment {
				row, err = repository.IncrementIf(key, condition, map[string]int32{"count": 1}, patch)
			} else {
				row, err = repository.UpdateIf(key, condition, patch)
			}
			if err != nil || string(row) != string(want) || calls != 1 {
				t.Fatalf("conditional result = %s, %v; calls = %d", row, err, calls)
			}
		})
	}
}

func TestORMMissingMutationResultsAndHostFailures(t *testing.T) {
	key := map[string]any{"tenant": "t", "id": int32(1)}
	condition := orm.Field[int32]{Name: "count"}.Gt(0)
	patch := map[string]any{"name": "n"}
	for _, failure := range []error{nil, &host.Error{Code: "40001"}, &host.Error{Code: "commit_unknown"}} {
		repository := repositoryForTest(t, func(string, []any) ([]json.RawMessage, error) { return []json.RawMessage{}, failure })
		for _, mutate := range []func() (json.RawMessage, error){
			func() (json.RawMessage, error) { return repository.Update(key, patch) },
			func() (json.RawMessage, error) { return repository.Increment(key, map[string]int32{"count": 1}) },
		} {
			row, err := mutate()
			if row != nil {
				t.Fatal("missing mutation fabricated a row")
			}
			if failure != nil {
				if !errors.Is(err, failure) {
					t.Fatalf("host error lost: %v", err)
				}
				continue
			}
			coded, ok := errors.AsType[*host.Error](err)
			if !ok || coded.Code != "not_found" {
				t.Fatalf("missing mutation must be coded not_found: %v", err)
			}
		}
		for _, mutate := range []func() (json.RawMessage, error){
			func() (json.RawMessage, error) { return repository.UpdateIf(key, condition, patch) },
			func() (json.RawMessage, error) {
				return repository.IncrementIf(key, condition, map[string]int32{"count": 1}, patch)
			},
			func() (json.RawMessage, error) { return repository.Delete(key) },
		} {
			row, err := mutate()
			if row != nil || !errors.Is(err, failure) {
				t.Fatalf("conditional/missing delete result = %s, %v", row, err)
			}
		}
	}
}

func TestORMDeleteReturnsDeletedRow(t *testing.T) {
	want := json.RawMessage(`{"tenant":"t","id":1,"name":"deleted","count":3,"created_at":"2026-10-26T00:00:00.000Z"}`)
	repository := repositoryForTest(t, func(sql string, params []any) ([]json.RawMessage, error) {
		if !strings.HasPrefix(sql, `delete from "items" where "tenant" = $1 and "id" = $2 returning "tenant", "id", "name", "count", "created_at"::text as "created_at"`) || !reflect.DeepEqual(params, []any{"t", float64(1)}) {
			t.Fatalf("delete: %s %v", sql, params)
		}
		return []json.RawMessage{want}, nil
	})
	row, err := repository.Delete(map[string]any{"tenant": "t", "id": int32(1)})
	if err != nil || string(row) != string(want) {
		t.Fatalf("deleted row = %s, %v", row, err)
	}
}
