package auth

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// Rules defines a ruleset by which a string can be validated.
// The errors it produces are english only, with some basic pluralization.
type Rules struct {
	// FieldName is the name of the field this is intended to validate.
	FieldName string

	// MatchError describes the MustMatch regexp to a user.
	Required             bool
	MatchError           string
	MustMatch            *regexp.Regexp
	MinLength, MaxLength int
	MinLetters           int
	MinLower, MinUpper   int
	MinNumeric           int
	MinSymbols           int
	AllowWhitespace      bool
}

// RegisterCustomValidators registers custom validators for gin binding.
//
// Supported custom tags:
//
//	letters=N      // At least N letters (upper or lower case)
//	lower=N        // At least N lowercase letters
//	upper=N        // At least N uppercase letters
//	numeric=N      // At least N digits
//	symbols=N      // At least N symbols (punctuation or special chars)
//	nowhitespace   // No whitespace allowed (space, tab, newline, etc)
//
// Example usage:
//
//	type RegisterRequest struct {
//	    Password string `json:"password" binding:"required,letters=2,lower=1,upper=1,numeric=1,symbols=1,nowhitespace"`
//	}
func RegisterCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("letters", validateMinLetters)
		v.RegisterValidation("lower", validateMinLower)
		v.RegisterValidation("upper", validateMinUpper)
		v.RegisterValidation("numeric", validateMinNumeric)
		v.RegisterValidation("symbols", validateMinSymbols)
		v.RegisterValidation("nowhitespace", validateNoWhitespace)
	}
}

func validateMinLetters(fl validator.FieldLevel) bool {
	min := 1
	if param := fl.Param(); param != "" {
		fmt.Sscanf(param, "%d", &min)
	}
	value := fl.Field().String()
	upper, lower, _, _, _ := tallyCharacters(value)
	return upper+lower >= min
}

func validateMinLower(fl validator.FieldLevel) bool {
	min := 1
	if param := fl.Param(); param != "" {
		fmt.Sscanf(param, "%d", &min)
	}
	value := fl.Field().String()
	_, lower, _, _, _ := tallyCharacters(value)
	return lower >= min
}

func validateMinUpper(fl validator.FieldLevel) bool {
	min := 1
	if param := fl.Param(); param != "" {
		fmt.Sscanf(param, "%d", &min)
	}
	value := fl.Field().String()
	upper, _, _, _, _ := tallyCharacters(value)
	return upper >= min
}

func validateMinNumeric(fl validator.FieldLevel) bool {
	min := 1
	if param := fl.Param(); param != "" {
		fmt.Sscanf(param, "%d", &min)
	}
	value := fl.Field().String()
	_, _, numeric, _, _ := tallyCharacters(value)
	return numeric >= min
}

func validateMinSymbols(fl validator.FieldLevel) bool {
	min := 1
	if param := fl.Param(); param != "" {
		fmt.Sscanf(param, "%d", &min)
	}
	value := fl.Field().String()
	_, _, _, symbols, _ := tallyCharacters(value)
	return symbols >= min
}

func validateNoWhitespace(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	_, _, _, _, whitespace := tallyCharacters(value)
	return whitespace == 0
}

// Errors returns an array of errors for each validation error that
// is present in the given string. Returns nil if there are no errors.
func (r Rules) Errors(toValidate string) []error {
	errList := make([]error, 0)
	ln := len(toValidate)
	if r.Required && ln == 0 {
		errList = append(errList, FieldError{r.FieldName, errors.New("cannot be blank")})
	}
	if (r.MinLength > 0 && ln < r.MinLength) || (r.MaxLength > 0 && ln > r.MaxLength) {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.lengthErr())})
	}
	upper, lower, numeric, symbols, whitespace := tallyCharacters(toValidate)
	if r.MinLetters > 0 && upper+lower < r.MinLetters {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.charErr())})
	}
	if r.MinUpper > 0 && upper < r.MinUpper {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.upperErr())})
	}
	if r.MinLower > 0 && lower < r.MinLower {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.lowerErr())})
	}
	if r.MinNumeric > 0 && numeric < r.MinNumeric {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.numericErr())})
	}
	if r.MinSymbols > 0 && symbols < r.MinSymbols {
		errList = append(errList, FieldError{r.FieldName, errors.New(r.symbolErr())})
	}
	if !r.AllowWhitespace && whitespace > 0 {
		errList = append(errList, FieldError{r.FieldName, errors.New("no whitespace permitted")})
	}
	if len(errList) == 0 {
		return nil
	}
	return errList
}

// IsValid checks toValidate to make sure it's valid according to the rules.
func (r Rules) IsValid(toValidate string) bool {
	return nil == r.Errors(toValidate)
}

// Rules returns an array of strings describing the rules.
func (r Rules) Rules() []string {
	var rules []string

	if r.MustMatch != nil {
		rules = append(rules, r.MatchError)
	}

	if e := r.lengthErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.charErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.upperErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.lowerErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.numericErr(); len(e) > 0 {
		rules = append(rules, e)
	}
	if e := r.symbolErr(); len(e) > 0 {
		rules = append(rules, e)
	}

	return rules
}

func (r Rules) lengthErr() (err string) {
	switch {
	case r.MinLength > 0 && r.MaxLength > 0:
		err = fmt.Sprintf("Must be between %d and %d characters", r.MinLength, r.MaxLength)
	case r.MinLength > 0:
		err = fmt.Sprintf("Must be at least %d character", r.MinLength)
		if r.MinLength > 1 {
			err += "s"
		}
	case r.MaxLength > 0:
		err = fmt.Sprintf("Must be at most %d character", r.MaxLength)
		if r.MaxLength > 1 {
			err += "s"
		}
	}

	return err
}

func (r Rules) charErr() (err string) {
	if r.MinLetters > 0 {
		err = fmt.Sprintf("Must contain at least %d letter", r.MinLetters)
		if r.MinLetters > 1 {
			err += "s"
		}
	}
	return err
}

func (r Rules) upperErr() (err string) {
	if r.MinUpper > 0 {
		err = fmt.Sprintf("Must contain at least %d uppercase letter", r.MinUpper)
		if r.MinUpper > 1 {
			err += "s"
		}
	}
	return err
}

func (r Rules) lowerErr() (err string) {
	if r.MinLower > 0 {
		err = fmt.Sprintf("Must contain at least %d lowercase letter", r.MinLower)
		if r.MinLower > 1 {
			err += "s"
		}
	}
	return err
}

func (r Rules) numericErr() (err string) {
	if r.MinNumeric > 0 {
		err = fmt.Sprintf("Must contain at least %d number", r.MinNumeric)
		if r.MinNumeric > 1 {
			err += "s"
		}
	}
	return err
}

func (r Rules) symbolErr() (err string) {
	if r.MinSymbols > 0 {
		err = fmt.Sprintf("Must contain at least %d symbol", r.MinSymbols)
		if r.MinSymbols > 1 {
			err += "s"
		}
	}
	return err
}

func tallyCharacters(s string) (upper, lower, numeric, symbols, whitespace int) {
	for _, c := range s {
		switch {
		case unicode.IsLetter(c):
			if unicode.IsUpper(c) {
				upper++
			} else {
				lower++
			}
		case unicode.IsDigit(c):
			numeric++
		case unicode.IsSpace(c):
			whitespace++
		default:
			symbols++
		}
	}

	return upper, lower, numeric, symbols, whitespace
}
