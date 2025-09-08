package auth

// A conscious decision was made to put all storer
// and user types into this file despite them truly
// belonging to outside modules. The reason for this
// is because documentation-wise, it was previously
// difficult to find what you had to implement or even
// what you could implement.

import (
	"context"
	"errors"
)

var (
	// ErrUserFound should be returned from Create (see ConfirmUser)
	// when the primaryID of the record is found.
	ErrUserFound = errors.New("user found")
	// ErrUserNotFound should be returned from Get when the record is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrTokenNotFound should be returned from UseToken when the
	// record is not found.
	ErrTokenNotFound = errors.New("token not found")
	// ErrCodeNotFound should be returned from UseCode when the
	// record is not found.
	ErrCodeNotFound = errors.New("code not found")

	ErrPIDNotFound = errors.New("pid not found")

	ErrUserAlreadyExists = errors.New("user already exists")
)

// ServerStorer represents the data store that's capable of loading users
// and giving them a context with which to store themselves.
type ServerStorer interface {
	// Load will look up the user based on the passed the PrimaryID. Under
	// normal circumstances this comes from GetPID() of the user.
	//
	// OAuth2 logins are special-cased to return an OAuth2 pid (combination of
	// provider:oauth2uid), and therefore key be special cased in a Load()
	// implementation to handle that form, use ParseOAuth2PID to see
	// if key is an OAuth2PID or not.
	Load(ctx context.Context, key string) (User, error)

	// Save persists the user in the database, this should never
	// create a user and instead return ErrUserNotFound if the user
	// does not exist.
	Save(ctx context.Context, user User) error

	// New creates a blank user, it is not yet persisted in the database
	// but is just for storing data
	New(ctx context.Context, pid string) User
	// Create the user in storage, it should not overwrite a user
	// and should return ErrUserFound if it currently exists.
	Create(ctx context.Context, user User) error
}

type LockServerStorer interface {
	// ServerStorer

	UpdateLoginLockedState(ctx context.Context, user User) error
	UpdateRecoverLockedState(ctx context.Context, user User) error
}

// OAuth2ServerStorer has the ability to create users from data from the provider.
//
// A correct implementation of OAuth2ServerStorer will have a Load() method
// that special cases the key parameter to be aware of possible OAuth2 pids
// by using the ParseOAuth2PID method.
type OAuth2ServerStorer interface {
	ServerStorer

	// NewFromOAuth2 should return an OAuth2User from a set
	// of details returned from OAuth2Provider.FindUserDetails
	// A more in-depth explanation is that once we've got an access token
	// for the service in question (say a service that rhymes with book)
	// the FindUserDetails function does an http request to a known endpoint
	// that provides details about the user, those details are captured in a
	// generic way as map[string]string and passed into this function to be
	// turned into a real user.
	//
	// It's possible that the user exists in the database already, and so
	// an attempt should be made to look that user up using the details.
	// Any details that have changed should be updated. Do not save the user
	// since that will be done later by OAuth2ServerStorer.SaveOAuth2()
	NewFromOAuth2(ctx context.Context, provider string, details map[string]string) (OAuth2User, error)

	// SaveOAuth2 has different semantics from the typical ServerStorer.Save,
	// in this case we want to insert a user if they do not exist.
	// The difference must be made clear because in the non-oauth2 case,
	// we know exactly when we want to Create vs Update. However since we're
	// simply trying to persist a user that may have been in our database,
	// but if not should already be (since you can think of the operation as
	// a caching of what's on the oauth2 provider's servers).
	SaveOAuth2(ctx context.Context, user OAuth2User) error
}

// ConfirmingServerStorer can find a user by a confirm token
type ConfirmingServerStorer interface {
	ServerStorer

	// LoadByConfirmSelector finds a user by his confirm selector field
	// and should return ErrUserNotFound if that user cannot be found.
	LoadByConfirmSelector(ctx context.Context, selector string) (ConfirmableUser, error)
}

// RecoveringServerStorer allows users to be recovered by a token
type RecoveringServerStorer interface {
	ServerStorer

	// LoadByRecoverSelector finds a user by his recover selector field
	// and should return ErrUserNotFound if that user cannot be found.
	LoadByRecoverSelector(ctx context.Context, selector string) (RecoverableUser, error)
}

// EnsureCanLock makes sure the server storer supports lock operations
func EnsureCanLock(storer ServerStorer) LockServerStorer {
	s, ok := storer.(LockServerStorer)
	if !ok {
		panic("could not upgrade ServerStorer to LockServerStorer, check your struct")
	}

	return s
}

// EnsureCanConfirm makes sure the server storer supports
// confirm-lookup operations
func EnsureCanConfirm(storer ServerStorer) ConfirmingServerStorer {
	s, ok := storer.(ConfirmingServerStorer)
	if !ok {
		panic("could not upgrade ServerStorer to ConfirmingServerStorer, check your struct")
	}

	return s
}

// EnsureCanRecover makes sure the server storer supports
// confirm-lookup operations
func EnsureCanRecover(storer ServerStorer) RecoveringServerStorer {
	s, ok := storer.(RecoveringServerStorer)
	if !ok {
		panic("could not upgrade ServerStorer to RecoveringServerStorer, check your struct")
	}

	return s
}

// EnsureCanOAuth2 makes sure the server storer supports
// oauth2 creation and lookup
func EnsureCanOAuth2(storer ServerStorer) OAuth2ServerStorer {
	s, ok := storer.(OAuth2ServerStorer)
	if !ok {
		panic("could not upgrade ServerStorer to OAuth2ServerStorer, check your struct")
	}

	return s
}
