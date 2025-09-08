package auth

import (
	"fmt"
	"strings"
	"time"
)

// User has functions for each piece of data it requires.
// Data should not be persisted on each function call.
// User has a PID (primary ID) that is used on the site as
// a single unique identifier to any given user (very typically e-mail
// or username).
//
// User interfaces return no errors or bools to signal that a value was
// not present. Instead 0-value = null = not present, this puts the onus
// on Authboss code to check for this.
type User interface {
	GetPID() (pid string)
	//	PutPID(pid string)

	// State() (state map[string]any)
}

// AuthableUser is identified by a password
type AuthableUser interface {
	User

	GetPassword() (password string)
	PutPassword(password string)
}

// ConfirmableUser can be in a state of confirmed or not
type ConfirmableUser interface {
	User

	GetEmail() (email string)
	GetConfirmed() (confirmed bool)
	//	GetConfirmSelector() (selector string)
	GetConfirmVerifier() (verifier string)

	PutEmail(email string)
	PutConfirmed(confirmed bool)
	//	PutConfirmSelector(selector string)
	PutConfirmVerifier(verifier string)
}

// LockableUser is a user that can be locked
type LoginLockableUser interface {
	User

	GetLoginAttemptCount() (attempts int)
	GetLoginLastAttempt() (last time.Time)
	GetLoginLockedUntil() (locked time.Time)

	PutLoginAttemptCount(attempts int)
	PutLoginLastAttempt(last time.Time)
	PutLoginLockedUntil(locked time.Time)
}

type RecoverLockableUser interface {
	User

	GetRecoverAttemptCount() (attempts int)
	GetRecoverLastAttempt() (last time.Time)
	GetRecoverLockedUntil() (locked time.Time)

	PutRecoverAttemptCount(attempts int)
	PutRecoverLastAttempt(last time.Time)
	PutRecoverLockedUntil(locked time.Time)
}

// RecoverableUser is a user that can be recovered via e-mail
type RecoverableUser interface {
	AuthableUser

	GetEmail() (email string)
	//GetRecoverSelector() (selector string)
	GetRecoverVerifier() (verifier string)
	GetRecoverExpiry() (expiry time.Time)

	GetResetToken() (token string)
	GetResetTokenExpiry() (expiry time.Time)

	PutEmail(email string)
	//PutRecoverSelector(selector string)
	PutRecoverVerifier(verifier string)
	PutRecoverExpiry(expiry time.Time)

	PutResetToken(token string)
	PutResetTokenExpiry(expiry time.Time)
}

type RecoverableUserWithSecondaryEmails interface {
	RecoverableUser

	GetSecondaryEmails() (secondaryEmails []string)
}

// ArbitraryUser allows arbitrary data from the web form through. You should
// definitely only pull the keys you want from the map, since this is unfiltered
// input from a web request and is an attack vector.
type ArbitraryUser interface {
	User

	// GetArbitrary is used only to display the arbitrary data back to the user
	// when the form is reset.
	GetArbitrary() (arbitrary map[string]string)
	// PutArbitrary allows arbitrary fields defined by the authboss library
	// consumer to add fields to the user registration piece.
	PutArbitrary(arbitrary map[string]string)
}

// OAuth2User allows reading and writing values relating to OAuth2
// Also see MakeOAuthPID/ParseOAuthPID for helpers to fulfill the User
// part of the interface.
type OAuth2User interface {
	User

	// IsOAuth2User checks to see if a user was registered in the site as an
	// oauth2 user.
	IsOAuth2User() bool

	GetOAuth2UID() (uid string)
	GetOAuth2Provider() (provider string)
	GetOAuth2AccessToken() (token string)
	GetOAuth2RefreshToken() (refreshToken string)
	GetOAuth2Expiry() (expiry time.Time)

	PutOAuth2UID(uid string)
	PutOAuth2Provider(provider string)
	PutOAuth2AccessToken(token string)
	PutOAuth2RefreshToken(refreshToken string)
	PutOAuth2Expiry(expiry time.Time)
}

// MustBeAuthable forces an upgrade to an AuthableUser or panic.
func MustBeAuthable(u User) AuthableUser {
	if au, ok := u.(AuthableUser); ok {
		return au
	}
	panic(fmt.Sprintf("could not upgrade user to an authable user, type: %T", u))
}

func BeConfirmableUser(u User) ConfirmableUser {
	if cu, ok := u.(ConfirmableUser); ok {
		return cu
	}

	return nil
}

// MustBeConfirmable forces an upgrade to a ConfirmableUser or panic.
func MustBeConfirmable(u User) ConfirmableUser {
	if cu, ok := u.(ConfirmableUser); ok {
		return cu
	}
	panic(fmt.Sprintf("could not upgrade user to a confirmable user, type: %T", u))
}

// MustBeLockable forces an upgrade to a LockableUser or panic.
func MustBeLoginLockable(u User) LoginLockableUser {
	if lu, ok := u.(LoginLockableUser); ok {
		return lu
	}
	panic(fmt.Sprintf("could not upgrade user to a lockable user, given type: %T", u))
}

// MustBeRecoverable forces an upgrade to a RecoverableUser or panic.
func MustBeRecoverable(u User) RecoverableUser {
	if lu, ok := u.(RecoverableUser); ok {
		return lu
	}
	panic(fmt.Sprintf("could not upgrade user to a recoverable user, given type: %T", u))
}

func MustBeRecoverLockable(u User) RecoverLockableUser {
	if lu, ok := u.(RecoverLockableUser); ok {
		return lu
	}
	panic(fmt.Sprintf("could not upgrade user to a recoverable user, given type: %T", u))
}

func CanBeRecoverableUserWithSecondaryEmails(u User) (RecoverableUserWithSecondaryEmails, bool) {
	if lu, ok := u.(RecoverableUserWithSecondaryEmails); ok {
		return lu, true
	}
	return nil, false
}

// MustBeOAuthable forces an upgrade to an OAuth2User or panic.
func MustBeOAuthable(u User) OAuth2User {
	if ou, ok := u.(OAuth2User); ok {
		return ou
	}
	panic(fmt.Sprintf("could not upgrade user to an oauthable user, given type: %T", u))
}

// MakeOAuth2PID is used to create a pid for users that don't have
// an e-mail address or username in the normal system. This allows
// all the modules to continue to working as intended without having
// a true primary id. As well as not having to divide the regular and oauth
// stuff all down the middle.
func MakeOAuth2PID(provider, uid string) string {
	return fmt.Sprintf("oauth2;;%s;;%s", provider, uid)
}

// ParseOAuth2PID returns the uid and provider for a given OAuth2 pid
func ParseOAuth2PID(pid string) (provider, uid string, err error) {
	splits := strings.Split(pid, ";;")
	if len(splits) != 3 {
		return "", "", fmt.Errorf("failed to parse oauth2 pid, too many segments: %s", pid)
	}
	if splits[0] != "oauth2" {
		return "", "", fmt.Errorf("invalid oauth2 pid, did not start with oauth2: %s", pid)
	}

	return splits[1], splits[2], nil
}

// ParseOAuth2PIDP returns the uid and provider for a given OAuth2 pid
func ParseOAuth2PIDP(pid string) (provider, uid string) {
	var err error
	provider, uid, err = ParseOAuth2PID(pid)
	if err != nil {
		panic(err)
	}

	return provider, uid
}
