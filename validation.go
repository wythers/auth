package auth

import "fmt"

// FieldError represents an error that occurs during validation and is always
// attached to field on a form.
type FieldError struct {
	FieldName string
	FieldErr  error
}

// NewFieldError literally only exists because of poor name planning
// where name and err can't be exported on the struct due to the method names
func NewFieldError(name string, err error) FieldError {
	return FieldError{FieldName: name, FieldErr: err}
}

// Name of the field the error is about
func (f FieldError) Name() string {
	return f.FieldName
}

// Err for the field
func (f FieldError) Err() error {
	return f.FieldErr
}

// Error in string form
func (f FieldError) Error() string {
	return fmt.Sprintf("%s: %v", f.FieldName, f.FieldErr)
}
