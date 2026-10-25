package orm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestComparisonFilters(t *testing.T) {
	repository := Repository{Table: Table{Columns: []Column{{Name: "count", Kind: "integer"}}}}
	field := Field[int32]{Name: "count"}
	for _, test := range []struct {
		name   string
		filter Filter
		want   string
		params []any
	}{
		{"equal", field.Eq(4), `"count" = $1`, []any{int32(4)}},
		{"not equal", field.Ne(4), `"count" <> $1`, []any{int32(4)}},
		{"greater", field.Gt(4), `"count" > $1`, []any{int32(4)}},
		{"greater or equal", field.Gte(4), `"count" >= $1`, []any{int32(4)}},
		{"less", field.Lt(4), `"count" < $1`, []any{int32(4)}},
		{"less or equal", field.Lte(4), `"count" <= $1`, []any{int32(4)}},
		{"membership", field.IsIn([]int32{4, 7}), `"count" in ($1, $2)`, []any{int32(4), int32(7)}},
		{"empty membership", field.IsIn(nil), "1 = 0", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var params []any
			sql, err := repository.filter(test.filter, &params, 0)
			if err != nil || sql != test.want || !reflect.DeepEqual(params, test.params) {
				t.Fatalf("filter = %q, %v, %v; want %q, %v", sql, params, err, test.want, test.params)
			}
		})
	}
	var params []any
	if _, err := repository.filter(Field[string]{Name: "count"}.IsIn([]string{"4"}), &params, 0); err == nil {
		t.Fatal("membership bypassed column type validation")
	}
}

func TestSchemaValidationBeforeIO(t *testing.T) {
	if err := validate(Column{Kind: "string"}, string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 silently replaced")
	}
	if err := validate(Column{Kind: "timestamp"}, "2026-10-14T00:00:00.1234567Z"); err == nil {
		t.Fatal("timestamp silently loses precision")
	}
	repository := Repository{Table: Table{Name: "items", Primary: []string{"id", "tenant"}, Columns: []Column{{Name: "id", Kind: "id", Primary: true}, {Name: "tenant", Kind: "string", Primary: true}, {Name: "name", Kind: "string"}, {Name: "count", Kind: "integer", Optional: true}}}}
	if _, _, _, err := repository.values(map[string]any{"id": "bad", "tenant": "t", "name": "n"}, true); err == nil {
		t.Fatal("invalid UUID accepted")
	}
	if _, _, _, err := repository.values(map[string]any{"id": "00000000-0000-0000-0000-000000000001"}, false); err == nil {
		t.Fatal("primary key patch accepted")
	}
	key := map[string]any{"id": "00000000-0000-0000-0000-000000000001", "tenant": "t"}
	for _, condition := range []Filter{{}, Field[string]{Name: "unknown"}.Eq("n")} {
		if _, err := repository.UpdateIf(key, condition, map[string]any{"name": "updated"}); err == nil {
			t.Fatal("conditional update accepted an invalid predicate before I/O")
		}
	}
	params := []any{}
	if _, err := repository.key(map[string]any{"id": "00000000-0000-0000-0000-000000000001"}, &params); err == nil {
		t.Fatal("incomplete composite key accepted")
	}
	columns, _, values, err := repository.values(map[string]any{"id": "00000000-0000-0000-0000-000000000001", "tenant": "t", "name": "'; drop table items;--"}, true)
	if err != nil || len(columns) != 3 || len(values) != 3 {
		t.Fatalf("default omission: %v %v", columns, err)
	}
	params = nil
	sql, err := repository.filter(And(Field[string]{Name: "name"}.Eq("' or true --"), Not(Field[int32]{Name: "count"}.Gt(4))), &params, 0)
	if err != nil || strings.Contains(sql, "true") || len(params) != 2 {
		t.Fatalf("unparameterized filter: %s %v", sql, err)
	}
	if _, err := repository.filter(Field[string]{Name: "unknown"}.Eq("n"), &params, 0); err == nil {
		t.Fatal("unknown column accepted")
	}

	if _, err := DecodeRow[struct{ ID string }](json.RawMessage(`{"id":"bad"}`), repository.Table); err == nil {
		t.Fatal("incomplete row accepted")
	}
	_, err = DecodeRow[struct {
		ID     string `json:"id"`
		Tenant string `json:"tenant"`
		Name   string `json:"name"`
		Count  int32  `json:"count"`
	}](json.RawMessage(`{"id":"00000000-0000-0000-0000-000000000001","tenant":"t","name":"n","count":2147483648}`), repository.Table)
	if err == nil {
		t.Fatal("out-of-range integer accepted")
	}
}

func TestDatabaseTemporalValuesStayDistinct(t *testing.T) {
	for input, want := range map[string]string{
		"2026-10-14 00:00:00.120000+00":       "2026-10-14T00:00:00.120Z",
		"2026-10-14 00:00:00+00":              "2026-10-14T00:00:00.000Z",
		"2026-10-14 00:00:00.000001+00":       "2026-10-14T00:00:00.000001Z",
		"2026-10-14 09:00:00.123450+09":       "2026-10-14T00:00:00.12345Z",
		"2026-10-14 00:00:30.123400+00:00:30": "2026-10-14T00:00:00.1234Z",
	} {
		value, err := normalizeTimestamp(input)
		if err != nil || value != want {
			t.Fatalf("%s: %s %v", input, value, err)
		}
	}
	table := Table{Columns: []Column{{Name: "stamp", Kind: "timestamp", Nullable: true}, {Name: "day", Kind: "date", Nullable: true}}}
	type row struct {
		Stamp *string `json:"stamp"`
		Day   *string `json:"day"`
	}
	value, err := DecodeRow[row](json.RawMessage(`{"stamp":null,"day":null}`), table)
	if err != nil || value.Stamp != nil || value.Day != nil {
		t.Fatalf("actual NULL changed: %v %v", value, err)
	}
	for _, input := range []string{
		`{"stamp":"infinity","day":null}`, `{"stamp":"-infinity","day":null}`,
		`{"stamp":null,"day":"infinity"}`, `{"stamp":null,"day":"-infinity"}`,
		`{"stamp":"0001-01-01 00:00:00+00 BC","day":null}`, `{"stamp":null,"day":"0001-01-01 BC"}`,
		`{"stamp":"2026-10-14 00:00:00.1234567+00","day":null}`, `{"stamp":"2026-10-14 00:00:00","day":null}`,
	} {
		if _, err := DecodeRow[row](json.RawMessage(input), table); err == nil {
			t.Fatalf("unsupported value became a normal row: %s", input)
		}
	}
}
