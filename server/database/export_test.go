package database

func NewTestConnection(call func(string, any) ([]byte, error)) *Connection {
	connection := New(1)
	connection.call = call
	return connection
}
