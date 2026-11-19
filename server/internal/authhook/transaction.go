// Package authhook carries the validated host grant within the server runtime.
package authhook

// Transaction identifies the host's current signup transaction.
type Transaction struct {
	requestID int64
	leaseID   int64
}

// NewTransaction records the handles accepted by the hook dispatcher.
func NewTransaction(requestID, leaseID int64) Transaction {
	return Transaction{requestID: requestID, leaseID: leaseID}
}

// Handles gives the database adapter the exact pair issued by the host.
func (transaction Transaction) Handles() (requestID, leaseID int64) {
	return transaction.requestID, transaction.leaseID
}
