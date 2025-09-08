package main

import (
	"context"

	"github.com/wythers/auth"
)

var (
	_ auth.ServerStorer     = (*Store)(nil)
	_ auth.LockServerStorer = (*Store)(nil)
)

var IDbase = 99999

var localstore = map[string]*User{}

type Store struct{}

// ServerStorer interface
func (s *Store) Load(_ context.Context, key string) (auth.User, error) {
	if user, ok := localstore[key]; ok {
		return user, nil
	}
	return nil, auth.ErrPIDNotFound
}

func (s *Store) Save(_ context.Context, user auth.User) error {
	if _, ok := localstore[user.GetPID()]; !ok {
		return auth.ErrPIDNotFound
	}
	localstore[user.GetPID()] = user.(*User)
	return nil
}

func (s *Store) New(_ context.Context, pid string) auth.User {
	IDbase++
	return &User{Email: pid, ID: IDbase}
}

func (s *Store) Create(_ context.Context, user auth.User) error {
	if _, ok := localstore[user.GetPID()]; ok {
		return auth.ErrUserAlreadyExists
	}
	localstore[user.GetPID()] = user.(*User)
	return nil
}

// LockServerStorer interface
func (s *Store) UpdateLoginLockedState(_ context.Context, user auth.User) error {
	if _, ok := localstore[user.GetPID()]; !ok {
		return auth.ErrPIDNotFound
	}
	lockable := auth.MustBeLoginLockable(user)
	localstore[user.GetPID()].AttemptCount = lockable.GetLoginAttemptCount()
	localstore[user.GetPID()].LastAttempt = lockable.GetLoginLastAttempt()
	localstore[user.GetPID()].Locked = lockable.GetLoginLockedUntil()
	return nil
}

func (s *Store) UpdateRecoverLockedState(_ context.Context, user auth.User) error {
	if _, ok := localstore[user.GetPID()]; !ok {
		return auth.ErrPIDNotFound
	}
	lockable := auth.MustBeRecoverLockable(user)
	localstore[user.GetPID()].RecoverAttemptCount = lockable.GetRecoverAttemptCount()
	localstore[user.GetPID()].RecoverLastAttempt = lockable.GetRecoverLastAttempt()
	localstore[user.GetPID()].RecoverLocked = lockable.GetRecoverLockedUntil()
	return nil
}
