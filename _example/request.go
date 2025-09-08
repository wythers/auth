package main

import (
	"github.com/wythers/auth/comfirm"
	"github.com/wythers/auth/login"
	"github.com/wythers/auth/recover"
	"github.com/wythers/auth/register"
)

var (
	_ login.Requester                = (*LoginRequest)(nil)
	_ register.Requester             = (*RegisterRequest)(nil)
	_ register.RequestWithPassworder = (*RegisterRequestWithPassworder)(nil)
	_ comfirm.Requester              = (*ComfirmRequest)(nil)
	_ recover.Requester              = (*RecoverRequest)(nil)
	_ recover.RequestWithCoder       = (*RecoverRequestWithCode)(nil)
	_ recover.RequestWithTokener     = (*RecoverRequestWithToken)(nil)
)

type Email struct {
	Email string `json:"pid" binding:"required,email"`
}

type Password struct {
	Password string `json:"password" binding:"required,min=8,max=128,lower=1,upper=1,numeric=1,symbols=1,nowhitespace"`
}

type Code struct {
	Code string `json:"code" binding:"required,min=6,max=6,numeric=6"`
}

type Token struct {
	Token string `json:"token" binding:"required,min=64,max=128"`
}

func (e Email) GetPID() string {
	return e.Email
}

func (p Password) GetPassword() string {
	return p.Password
}

func (c Code) GetCode() string {
	return c.Code
}

func (t Token) GetToken() string {
	return t.Token
}

/*
---- LoginRequest ----
*/
type LoginRequest struct {
	Email
	Password
}

/*
---- RegisterRequest ----
*/
type RegisterRequest struct {
	Email
}

/*
---- RegisterRequestWithPassworder ----
*/
type RegisterRequestWithPassworder struct {
	Email
	Password
}

/*
---- ComfirmRequest ----
*/
type ComfirmRequest struct {
	Email
	Code
}

/*
---- RecoverRequest ----
*/
type RecoverRequest struct {
	Email
}

/*
---- RecoverRequestWithCode ----
*/
type RecoverRequestWithCode struct {
	Email
	Code
}

/*
---- RecoverRequestWithToken ----
*/
type RecoverRequestWithToken struct {
	Email
	Token
	Password
}
