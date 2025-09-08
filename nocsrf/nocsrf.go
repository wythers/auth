package nocsrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
)

type csrfContext struct {
	// The masked, base64 encoded token
	// That's suitable for use in form fields, etc.
	token string
	// reason for the failure of CSRF check
	reason error
}

const (
	// the name of CSRF cookie
	CookieName = "csrf_token"
	// the name of the form field
	FormFieldName = "csrf_token"
	// the name of CSRF header
	HeaderName = "X-CSRF-Token"
	// the HTTP status code for the default failure handler
	FailureCode = 400

	tokenLength = 32

	// Max-Age in seconds for the default base cookie. 365 days.
	MaxAge = 365 * 24 * 60 * 60
)

// var safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// reasons for CSRF check failures
var (
	ErrNoReferer  = errors.New("a secure request contained no Referer or its value was malformed")
	ErrBadReferer = errors.New("a secure request's Referer comes from a different Origin" +
		" from the request's URL")
	ErrBadToken = errors.New("the CSRF token in the cookie doesnt match the one received in a form/header")
)

func Middleware(e *auth.Engine) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		noCSRFContextMiddleware,
		maskedTokenMiddleware,
	}
}

func MustNoCSRFMiddleware(e *auth.Engine) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		noCSRFContextMiddleware,
		varifyCSRFMiddleware,
	}
}

func noCSRFContextMiddleware(c *gin.Context) {
	addNosurfContext(c)
	c.Header("Vary", "Cookie")

	var realToken []byte

	tokenCookie, err := c.Cookie(CookieName)
	if err == nil {
		realToken = b64decode(tokenCookie)
	}

	// If the length of the real token isn't what it should be,
	// it has either been tampered with,
	// or we're migrating onto a new algorithm for generating tokens,
	// or it hasn't ever been set so far.
	// In any case of those, we should regenerate it.
	//
	// As a consequence, CSRF check will fail when comparing the tokens later on,
	// so we don't have to fail it just yet.
	if len(realToken) != tokenLength {
		RegenerateToken(c)
	} else {
		ctxSetToken(c, realToken)
	}
}

func varifyCSRFMiddleware(c *gin.Context) {
	// if the request is secure, we enforce origin check
	// for referer to prevent MITM of http->https requests
	if c.Request.URL.Scheme == "https" {
		referer, err := url.Parse(c.GetHeader("Referer"))

		// if we can't parse the referer or it's empty,
		// we assume it's not specified
		if err != nil || referer.String() == "" {
			ctxSetReason(c, ErrNoReferer)
			c.AbortWithStatus(http.StatusForbidden) // 403 Forbidden for CSRF errors
			return
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, c.Request.URL) {
			ctxSetReason(c, ErrBadReferer)
			c.AbortWithStatus(http.StatusForbidden) // 403 Forbidden for CSRF errors
			return
		}
	}

	realToken := b64decode(ctxGetToken(c))

	// Finally, we check the token itself.
	sentToken := extractToken(c.Request)

	if !verifyToken(realToken, sentToken) {
		ctxSetReason(c, ErrBadToken)

		c.AbortWithStatus(http.StatusForbidden) // 403 Forbidden for CSRF errors
	}
}

func maskedTokenMiddleware(c *gin.Context) {
	// ctxGetToken returns base64 encoded unmasked token
	tokenB64 := ctxGetToken(c)
	realToken := b64decode(tokenB64)
	masked := maskToken(realToken)
	auth.SetState(c, auth.Auth_CSRFToken, b64encode(masked))
}

// handleSuccess simply calls the successHandler.
// Everything else, like setting a token in the context
// is taken care of by h.ServeHTTP()
// func (h *CSRFHandler) handleSuccess(w http.ResponseWriter, r *http.Request) {
// 	h.successHandler.ServeHTTP(w, r)
// }

// // Same applies here: h.ServeHTTP() sets the failure reason, the token,
// // and only then calls handleFailure()
// func (h *CSRFHandler) handleFailure(w http.ResponseWriter, r *http.Request) {
// 	h.failureHandler.ServeHTTP(w, r)
// }

// Generates a new token, sets it on the given request and returns it
func RegenerateToken(c *gin.Context) string {
	token := generateToken()
	setTokenCookie(c, token)

	return Token(c)
}

func setTokenCookie(c *gin.Context, token []byte) {
	// ctxSetToken() does the masking for us
	ctxSetToken(c, token)

	cookie := http.Cookie{}
	cookie.MaxAge = MaxAge
	cookie.Name = CookieName
	cookie.Value = b64encode(token)

	c.SetCookie(cookie.Name, cookie.Value, cookie.MaxAge, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly)
}

/*
There are two types of tokens.

* The unmasked "real" token consists of 32 random bytes.
  It is stored in a cookie (base64-encoded) and it's the
  "reference" value that sent tokens get compared to.

* The masked "sent" token consists of 64 bytes:
  32 byte key used for one-time pad masking and
  32 byte "real" token masked with the said key.
  It is used as a value (base64-encoded as well)
  in forms and/or headers.

Upon processing, both tokens are base64-decoded
and then treated as 32/64 byte slices.
*/

// A token is generated by returning tokenLength bytes
// from crypto/rand
func generateToken() []byte {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	return bytes
}

func b64encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64decode(data string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return decoded
}

// VerifyToken verifies the sent token equals the real one
// and returns a bool value indicating if tokens are equal.
// Supports masked tokens. realToken comes from Token(r) and
// sentToken is token sent unusual way.
func VerifyToken(realToken, sentToken string) bool {
	r, err := base64.StdEncoding.DecodeString(realToken)
	if err != nil {
		return false
	}
	if len(r) == 2*tokenLength {
		r = unmaskToken(r)
	}
	s, err := base64.StdEncoding.DecodeString(sentToken)
	if err != nil {
		return false
	}
	if len(s) == 2*tokenLength {
		s = unmaskToken(s)
	}
	return tokensEqual(r, s)
}

// verifyToken expects the realToken to be unmasked and the sentToken to be masked
func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)

	// sentN == tokenLength means the token is unmasked
	// sentN == 2*tokenLength means the token is masked.

	if realN == tokenLength && sentN == 2*tokenLength {
		return tokensEqual(realToken, unmaskToken(sentToken))
	}
	return false
}

// tokensEqual expects both tokens to be unmasked
func tokensEqual(realToken, sentToken []byte) bool {
	return len(realToken) == tokenLength &&
		len(sentToken) == tokenLength &&
		subtle.ConstantTimeCompare(realToken, sentToken) == 1
}

// Token takes an HTTP request and returns
// the CSRF token for that request
// or an empty string if the token does not exist.
//
// Note that the token won't be available after
// CSRFHandler finishes
// (that is, in another handler that wraps it,
// or after the request has been served)
func Token(c *gin.Context) string {
	ctx, ok := c.MustGet(string(auth.CTXKeyCSRFToken)).(*csrfContext)
	if !ok {
		return ""
	}

	return ctx.token
}

// Reason takes an HTTP request and returns
// the reason of failure of the CSRF check for that request
//
// Note that the same availability restrictions apply for Reason() as for Token().
func Reason(c *gin.Context) error {
	ctx := c.MustGet(string(auth.CTXKeyCSRFToken)).(*csrfContext)

	return ctx.reason
}

func ctxSetToken(c *gin.Context, token []byte) {
	// ctx := req.Context().Value(nosurfKey).(*csrfContext)
	// ctx.token = b64encode(maskToken(token))
	ctx := c.MustGet(string(auth.CTXKeyCSRFToken)).(*csrfContext)
	ctx.token = b64encode(token) // Store base64 encoded token for safe string handling
}

func ctxGetToken(c *gin.Context) string {
	ctx := c.MustGet(string(auth.CTXKeyCSRFToken)).(*csrfContext)
	return ctx.token
}

func ctxSetReason(c *gin.Context, reason error) {
	ctx := c.MustGet(string(auth.CTXKeyCSRFToken)).(*csrfContext)
	ctx.reason = reason
}

func addNosurfContext(c *gin.Context) *gin.Context {
	c.Set(string(auth.CTXKeyCSRFToken), &csrfContext{})
	return c
}

func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	key := data[:tokenLength]
	token := data[tokenLength:]
	oneTimePad(token, key)

	return token
}

func maskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	// tokenLength*2 == len(enckey + token)
	result := make([]byte, 2*tokenLength)
	// the first half of the result is the OTP
	// the second half is the masked token itself
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	// generate the random token
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	oneTimePad(token, key)
	return result
}

func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

// Checks if the given URLs have the same origin
// (that is, they share the host, the port and the scheme)
func sameOrigin(u1, u2 *url.URL) bool {
	// we take pointers, as url.Parse() returns a pointer
	// and http.Request.URL is a pointer as well

	// Host is either host or host:port
	return (u1.Scheme == u2.Scheme && u1.Host == u2.Host)
}

// Extracts the "sent" token from the request
// and returns an unmasked version of it
func extractToken(r *http.Request) []byte {
	// Prefer the header over form value
	sentToken := r.Header.Get(HeaderName)

	// Then POST values
	if len(sentToken) == 0 {
		sentToken = r.PostFormValue(FormFieldName)
	}

	// If all else fails, try a multipart value.
	// PostFormValue() will already have called ParseMultipartForm()
	if len(sentToken) == 0 && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[FormFieldName]
		if len(vals) != 0 {
			sentToken = vals[0]
		}
	}

	return b64decode(sentToken)
}
