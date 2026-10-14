// Package orm executes the schema-bound queries exposed by generated repositories.
package orm

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chickinfry/chickinfry-go/server/database"
	"github.com/chickinfry/chickinfry-go/server/host"
)

// Optional distinguishes omitted values from an explicit SQL null.
type Optional[T any] struct {
	Set   bool
	Null  bool
	Value T
}

// Column describes one generated schema column.
type Column struct {
	Name, Kind                  string
	Nullable, Optional, Primary bool
}

// Table carries generated schema metadata, never customer SQL.
type Table struct {
	Name    string
	Columns []Column
	Primary []string
}

// Field provides typed predicates for one generated column.
type Field[T any] struct{ Name string }

func (field Field[T]) Equal(value T) Filter {
	return Filter{column: field.Name, operator: "=", value: value}
}
func (field Field[T]) Greater(value T) Filter {
	return Filter{column: field.Name, operator: ">", value: value}
}
func (field Field[T]) Less(value T) Filter {
	return Filter{column: field.Name, operator: "<", value: value}
}
func (field Field[T]) IsNull() Filter    { return Filter{column: field.Name, operator: "is null"} }
func (field Field[T]) IsNotNull() Filter { return Filter{column: field.Name, operator: "is not null"} }
func (field Field[T]) Asc() Order        { return Order{column: field.Name} }
func (field Field[T]) Desc() Order       { return Order{column: field.Name, descending: true} }

// Filter is a generated-column predicate or a composition of predicates.
type Filter struct {
	column, operator string
	value            any
	children         []Filter
}

func And(filters ...Filter) Filter { return Filter{operator: "and", children: filters} }
func Or(filters ...Filter) Filter  { return Filter{operator: "or", children: filters} }
func Not(filter Filter) Filter     { return Filter{operator: "not", children: []Filter{filter}} }

// Order specifies a validated generated column and sort direction.
type Order struct {
	column     string
	descending bool
}

// FindMany defines typed filtering and pagination.
type FindMany struct {
	Where         Filter
	Order         []Order
	Limit, Offset *int32
}

// Repository binds one generated table to a request or transaction connection.
type Repository struct {
	Connection *database.Connection
	Table      Table
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
var timestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$`)
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func quote(name string) (string, error) {
	if !identifier.MatchString(name) || len(name) > 63 {
		return "", errors.New("invalid ORM identifier")
	}
	return `"` + name + `"`, nil
}

func (repository Repository) column(name string) (Column, error) {
	for _, column := range repository.Table.Columns {
		if column.Name == name {
			return column, nil
		}
	}
	return Column{}, errors.New("unknown ORM column")
}

func validate(column Column, value any) error {
	if value == nil {
		if column.Nullable {
			return nil
		}
		return errors.New("column cannot be null")
	}
	switch column.Kind {
	case "integer":
		if _, ok := value.(int32); !ok {
			return errors.New("integer must be int32")
		}
	case "id", "string", "date", "timestamp":
		text, ok := value.(string)
		if !ok || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return errors.New("invalid ORM string")
		}
		switch column.Kind {
		case "id":
			if !uuid.MatchString(text) {
				return errors.New("invalid ORM UUID")
			}
		case "date":
			if value, err := time.Parse("2006-01-02", text); err != nil || value.Year() < 1 {
				return errors.New("invalid ORM date")
			}
		case "timestamp":
			if value, err := time.Parse(time.RFC3339Nano, text); err != nil || !timestamp.MatchString(text) || value.Year() < 1 || value.UTC().Year() < 1 || value.UTC().Year() > 9999 {
				return errors.New("invalid ORM timestamp")
			}
		}
	default:
		return errors.New("unknown ORM type")
	}
	return nil
}

func (repository Repository) selection() (string, error) {
	columns := []string{}
	for _, column := range repository.Table.Columns {
		name, err := quote(column.Name)
		if err != nil {
			return "", err
		}
		if column.Kind == "timestamp" || column.Kind == "date" {
			name = name + "::text as " + name
		}
		columns = append(columns, name)
	}
	if len(columns) == 0 {
		return "", errors.New("empty ORM table")
	}
	return strings.Join(columns, ", "), nil
}

func (repository Repository) values(values map[string]any, insert bool) ([]string, []string, []any, error) {
	if values == nil {
		return nil, nil, nil, errors.New("missing ORM values")
	}
	for name, value := range values {
		column, err := repository.column(name)
		if err != nil {
			return nil, nil, nil, err
		}
		if !insert && column.Primary {
			return nil, nil, nil, errors.New("primary key is immutable")
		}
		if err := validate(column, value); err != nil {
			return nil, nil, nil, err
		}
	}
	columns, placeholders, params := []string{}, []string{}, []any{}
	for _, column := range repository.Table.Columns {
		value, ok := values[column.Name]
		if !ok {
			if insert && !column.Optional {
				return nil, nil, nil, errors.New("missing insert column")
			}
			continue
		}
		name, err := quote(column.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		columns = append(columns, name)
		params = append(params, value)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(params)))
	}
	return columns, placeholders, params, nil
}

// Insert returns the row inserted using validated, parameterized values.
func (repository Repository) Insert(values map[string]any) (json.RawMessage, error) {
	table, err := quote(repository.Table.Name)
	if err != nil {
		return nil, err
	}
	columns, placeholders, params, err := repository.values(values, true)
	if err != nil {
		return nil, err
	}
	selection, err := repository.selection()
	if err != nil {
		return nil, err
	}
	sql := "insert into " + table + " default values"
	if len(columns) > 0 {
		sql = "insert into " + table + " (" + strings.Join(columns, ", ") + ") values (" + strings.Join(placeholders, ", ") + ")"
	}
	rows, err := repository.Connection.Query(sql+" returning "+selection, params)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("insert did not return one row")
	}
	return rows[0], nil
}

func (repository Repository) key(key map[string]any, params *[]any) (string, error) {
	if len(key) != len(repository.Table.Primary) || len(key) == 0 {
		return "", errors.New("complete primary key required")
	}
	conditions := []string{}
	for _, name := range repository.Table.Primary {
		value, ok := key[name]
		if !ok {
			return "", errors.New("complete primary key required")
		}
		column, err := repository.column(name)
		if err != nil {
			return "", err
		}
		if err := validate(column, value); err != nil {
			return "", err
		}
		quoted, err := quote(name)
		if err != nil {
			return "", err
		}
		*params = append(*params, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", quoted, len(*params)))
	}
	return strings.Join(conditions, " and "), nil
}

// FindByID returns nil when the complete primary key has no row.
func (repository Repository) FindByID(key map[string]any) (json.RawMessage, error) {
	params := []any{}
	where, err := repository.key(key, &params)
	if err != nil {
		return nil, err
	}
	table, err := quote(repository.Table.Name)
	if err != nil {
		return nil, err
	}
	selection, err := repository.selection()
	if err != nil {
		return nil, err
	}
	rows, err := repository.Connection.Query("select "+selection+" from "+table+" where "+where, params)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 {
		return nil, errors.New("primary key returned multiple rows")
	}
	return rows[0], nil
}

func (repository Repository) filter(filter Filter, params *[]any, depth int) (string, error) {
	if depth > 64 {
		return "", errors.New("ORM filter too deep")
	}
	if filter.operator == "" {
		return "", nil
	}
	if filter.operator == "and" || filter.operator == "or" || filter.operator == "not" {
		if len(filter.children) == 0 || filter.operator == "not" && len(filter.children) != 1 {
			return "", errors.New("invalid ORM filter")
		}
		parts := []string{}
		for _, child := range filter.children {
			part, err := repository.filter(child, params, depth+1)
			if err != nil || part == "" {
				return "", errors.New("invalid ORM filter")
			}
			parts = append(parts, part)
		}
		if filter.operator == "not" {
			return "not (" + parts[0] + ")", nil
		}
		return "(" + strings.Join(parts, " "+filter.operator+" ") + ")", nil
	}
	column, err := repository.column(filter.column)
	if err != nil {
		return "", err
	}
	name, err := quote(filter.column)
	if err != nil {
		return "", err
	}
	if filter.operator == "is null" || filter.operator == "is not null" {
		return name + " " + filter.operator, nil
	}
	if !slices.Contains([]string{"=", ">", "<"}, filter.operator) {
		return "", errors.New("invalid ORM operator")
	}
	if filter.value == nil {
		return "", errors.New("use a null predicate")
	}
	if err := validate(column, filter.value); err != nil {
		return "", err
	}
	*params = append(*params, filter.value)
	return fmt.Sprintf("%s %s $%d", name, filter.operator, len(*params)), nil
}

// Find returns the ordered rows matching typed predicates.
func (repository Repository) Find(options FindMany) ([]json.RawMessage, error) {
	table, err := quote(repository.Table.Name)
	if err != nil {
		return nil, err
	}
	selection, err := repository.selection()
	if err != nil {
		return nil, err
	}
	params := []any{}
	where, err := repository.filter(options.Where, &params, 0)
	if err != nil {
		return nil, err
	}
	sql := "select " + selection + " from " + table
	if where != "" {
		sql += " where " + where
	}
	orders := []string{}
	for _, order := range options.Order {
		if _, err := repository.column(order.column); err != nil {
			return nil, err
		}
		name, err := quote(order.column)
		if err != nil {
			return nil, err
		}
		if order.descending {
			name += " desc"
		} else {
			name += " asc"
		}
		orders = append(orders, name)
	}
	if len(orders) > 0 {
		sql += " order by " + strings.Join(orders, ", ")
	}
	for _, item := range []struct {
		name  string
		value *int32
	}{{"limit", options.Limit}, {"offset", options.Offset}} {
		if item.value != nil {
			if *item.value < 0 {
				return nil, errors.New("negative ORM pagination")
			}
			params = append(params, *item.value)
			sql += fmt.Sprintf(" %s $%d", item.name, len(params))
		}
	}
	return repository.Connection.Query(sql, params)
}

// Update changes mutable columns on exactly one primary-key-addressed row.
func (repository Repository) Update(key, patch map[string]any) (json.RawMessage, error) {
	table, err := quote(repository.Table.Name)
	if err != nil {
		return nil, err
	}
	columns, placeholders, params, err := repository.values(patch, false)
	if err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, errors.New("empty ORM update")
	}
	sets := []string{}
	for index, column := range columns {
		sets = append(sets, column+" = "+placeholders[index])
	}
	where, err := repository.key(key, &params)
	if err != nil {
		return nil, err
	}
	selection, err := repository.selection()
	if err != nil {
		return nil, err
	}
	rows, err := repository.Connection.Query("update "+table+" set "+strings.Join(sets, ", ")+" where "+where+" returning "+selection, params)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("update did not return one row")
	}
	return rows[0], nil
}

// Delete removes at most one primary-key-addressed row.
func (repository Repository) Delete(key map[string]any) (bool, error) {
	table, err := quote(repository.Table.Name)
	if err != nil {
		return false, err
	}
	params := []any{}
	where, err := repository.key(key, &params)
	if err != nil {
		return false, err
	}
	rows, err := repository.Connection.Query("delete from "+table+" where "+where+" returning 1 as deleted", params)
	if err != nil {
		return false, err
	}
	if len(rows) > 1 {
		return false, errors.New("delete returned multiple rows")
	}
	return len(rows) == 1, nil
}

// DecodeRow rejects missing or null required columns before publishing a typed row.
func DecodeRow[T any](data json.RawMessage, table Table) (T, error) {
	var row T
	var object map[string]json.RawMessage
	if host.Decode(data, &object) != nil || object == nil || len(object) != len(table.Columns) {
		return row, errors.New("invalid ORM row")
	}
	for _, column := range table.Columns {
		raw, ok := object[column.Name]
		if !ok {
			return row, errors.New("missing ORM row column")
		}
		if string(raw) == "null" {
			if !column.Nullable {
				return row, errors.New("null ORM row column")
			}
			continue
		}
		var value any
		if column.Kind == "integer" {
			var integer int32
			if json.Unmarshal(raw, &integer) != nil {
				return row, errors.New("invalid ORM row integer")
			}
			value = integer
		} else {
			var text string
			if json.Unmarshal(raw, &text) != nil {
				return row, errors.New("invalid ORM row string")
			}
			value = text
		}
		if column.Kind == "timestamp" {
			normalized, err := normalizeTimestamp(value.(string))
			if err != nil {
				return row, err
			}
			value = normalized
			object[column.Name], err = json.Marshal(normalized)
			if err != nil {
				return row, err
			}
		}
		if err := validate(column, value); err != nil {
			return row, err
		}
	}
	normalized, err := json.Marshal(object)
	if err != nil {
		return row, err
	}
	return row, host.Decode(normalized, &row)
}

var databaseTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}(?::\d{2}(?::\d{2})?)?)$`)

func normalizeTimestamp(text string) (string, error) {
	if !databaseTimestamp.MatchString(text) {
		return "", errors.New("unsupported database timestamp")
	}
	text = strings.Replace(text, " ", "T", 1)
	layout := time.RFC3339Nano
	zone := strings.LastIndexAny(text, "+-")
	if zone > 10 {
		switch len(text) - zone {
		case 3:
			text += ":00"
		case 9:
			layout = "2006-01-02T15:04:05.999999999Z07:00:00"
		}
	}
	value, err := time.Parse(layout, text)
	if err != nil || value.Year() < 1 || value.Year() > 9999 || value.UTC().Year() < 1 || value.UTC().Year() > 9999 {
		return "", errors.New("unsupported database timestamp")
	}
	fraction := strings.TrimRight(fmt.Sprintf("%06d", value.Nanosecond()/1000), "0")
	if len(fraction) < 3 {
		fraction += strings.Repeat("0", 3-len(fraction))
	}
	return value.UTC().Format("2006-01-02T15:04:05") + "." + fraction + "Z", nil
}
