package errors

type APIError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func NewAPIError(status int, message string, code string) *APIError {
	return &APIError{
		Status:  status,
		Message: message,
		Code:    code,
	}
}
