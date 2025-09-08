package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
)

func TestCustomValidatorsWithGin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth.RegisterCustomValidators()

	type Req struct {
		Password string `json:"password" binding:"required,letters=2,lower=1,upper=1,numeric=1,symbols=1,nowhitespace"`
	}

	tests := []struct {
		json       string
		shouldPass bool
	}{
		{`{"password":"Ab1!"}`, true},
		{`{"password":"ab1!"}`, false},
		{`{"password":"AB1!"}`, false},
		{`{"password":"Abc!"}`, false},
		{`{"password":"Ab12"}`, false},
		{`{"password":"Ab1!"}`, false},
		{`{"password":"A1!"}`, false},
	}

	for _, tc := range tests {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/", strings.NewReader(tc.json))
		c.Request.Header.Set("Content-Type", "application/json")
		var req Req
		err := c.ShouldBind(&req)
		if tc.shouldPass && err != nil {
			t.Errorf("input %s should pass, but failed: %v", tc.json, err)
		}
		if !tc.shouldPass && err == nil {
			t.Errorf("input %s should fail, but passed", tc.json)
		}
	}
}
