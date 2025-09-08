package main

import (
	"time"

	"github.com/wythers/auth"
)

var (
	_ auth.User                = (*User)(nil)
	_ auth.AuthableUser        = (*User)(nil)
	_ auth.ConfirmableUser     = (*User)(nil)
	_ auth.LoginLockableUser   = (*User)(nil)
	_ auth.RecoverLockableUser = (*User)(nil)
	_ auth.RecoverableUser     = (*User)(nil)
	_ auth.OAuth2User          = (*User)(nil)
)

// User struct for authboss
type User struct {
	ID int

	// Non-authboss related field
	Name string

	// Auth
	Email    string
	Password string

	// Confirm
	ConfirmSelector string
	ConfirmVerifier string
	Confirmed       bool

	// Lock
	AttemptCount int
	LastAttempt  time.Time
	Locked       time.Time

	// Recover Lock
	RecoverAttemptCount int
	RecoverLastAttempt  time.Time
	RecoverLocked       time.Time

	// Recover
	RecoverSelector    string
	RecoverVerifier    string
	RecoverTokenExpiry time.Time
	ResetToken         string
	ResetTokenExpiry   time.Time

	// OAuth2
	OAuth2UID          string
	OAuth2Provider     string
	OAuth2AccessToken  string
	OAuth2RefreshToken string
	OAuth2Expiry       time.Time

	// 2fa
	TOTPSecretKey      string
	SMSPhoneNumber     string
	SMSSeedPhoneNumber string
	RecoveryCodes      string
}

func (u User) GetPID() string {
	return u.Email
}

// AuthableUser interface
func (u User) GetPassword() string {
	return u.Password
}

func (u *User) PutPassword(password string) {
	u.Password = password
}

// ConfirmableUser interface
func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetConfirmed() bool {
	return u.Confirmed
}

func (u User) GetConfirmVerifier() string {
	return u.ConfirmVerifier
}

func (u *User) PutEmail(email string) {
	u.Email = email
}

func (u *User) PutConfirmed(confirmed bool) {
	u.Confirmed = confirmed
}

func (u *User) PutConfirmVerifier(verifier string) {
	u.ConfirmVerifier = verifier
}

// LoginLockableUser interface
func (u User) GetLoginAttemptCount() int {
	return u.AttemptCount
}

func (u User) GetLoginLastAttempt() time.Time {
	return u.LastAttempt
}

func (u User) GetLoginLockedUntil() time.Time {
	return u.Locked
}

func (u *User) PutLoginAttemptCount(attempts int) {
	u.AttemptCount = attempts
}

func (u *User) PutLoginLastAttempt(last time.Time) {
	u.LastAttempt = last
}

func (u *User) PutLoginLockedUntil(locked time.Time) {
	u.Locked = locked
}

// RecoverableUser interface
func (u User) GetRecoverVerifier() string {
	return u.RecoverVerifier
}

func (u User) GetRecoverExpiry() time.Time {
	return u.RecoverTokenExpiry
}

func (u User) GetResetToken() string {
	return u.ResetToken
}

func (u User) GetResetTokenExpiry() time.Time {
	return u.ResetTokenExpiry
}

func (u *User) PutRecoverVerifier(verifier string) {
	u.RecoverVerifier = verifier
}

func (u *User) PutRecoverExpiry(expiry time.Time) {
	u.RecoverTokenExpiry = expiry
}

func (u *User) PutResetToken(token string) {
	u.ResetToken = token
}

func (u *User) PutResetTokenExpiry(expiry time.Time) {
	u.ResetTokenExpiry = expiry
}

// OAuth2User interface
func (u *User) IsOAuth2User() bool {
	return u.OAuth2Provider != "" && u.OAuth2UID != ""
}

func (u User) GetOAuth2UID() string {
	return u.OAuth2UID
}

func (u User) GetOAuth2Provider() string {
	return u.OAuth2Provider
}

func (u User) GetOAuth2AccessToken() string {
	return u.OAuth2AccessToken
}

func (u User) GetOAuth2RefreshToken() string {
	return u.OAuth2RefreshToken
}

func (u User) GetOAuth2Expiry() time.Time {
	return u.OAuth2Expiry
}

func (u *User) PutOAuth2UID(uid string) {
	u.OAuth2UID = uid
}

func (u *User) PutOAuth2Provider(provider string) {
	u.OAuth2Provider = provider
}

func (u *User) PutOAuth2AccessToken(token string) {
	u.OAuth2AccessToken = token
}

func (u *User) PutOAuth2RefreshToken(refreshToken string) {
	u.OAuth2RefreshToken = refreshToken
}

func (u *User) PutOAuth2Expiry(expiry time.Time) {
	u.OAuth2Expiry = expiry
}

// RecoverLockableUser interface
func (u User) GetRecoverAttemptCount() int {
	return u.RecoverAttemptCount
}

func (u User) GetRecoverLastAttempt() time.Time {
	return u.RecoverLastAttempt
}

func (u User) GetRecoverLockedUntil() time.Time {
	return u.RecoverLocked
}

func (u *User) PutRecoverAttemptCount(attempts int) {
	u.RecoverAttemptCount = attempts
}

func (u *User) PutRecoverLastAttempt(last time.Time) {
	u.RecoverLastAttempt = last
}

func (u *User) PutRecoverLockedUntil(locked time.Time) {
	u.RecoverLocked = locked
}
