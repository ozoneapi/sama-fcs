package model

// ResourceIDs -
type ResourceIDs struct {
	AccountIDs   []ResourceAccountID   `json:"account_ids"`
	StatementIDs []ResourceStatementID `json:"statement_ids"`
}

// ResourceAccountID -
type ResourceAccountID struct {
	AccountID string `json:"account_id"`
}

// ResourceStatementID -
type ResourceStatementID struct {
	StatementID string `json:"statement_id"`
}
