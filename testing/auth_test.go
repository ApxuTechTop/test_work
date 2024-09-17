package test

import (
	"test_auth/auth"
	"testing"
)

type fakeDb struct {
	storage map[string][]string
}

func (d fakeDb) Save(user_id string, hashToken string) {

}

type errorHandlers struct {
	IpHandler func()
}

func (e errorHandlers) OnIp(expected string, received string) bool {
	e.IpHandler()
	return true
}
func (e errorHandlers) OnExp(expected int64, received int64) bool {
	return false
}
func (e errorHandlers) OnId(expected string, received string) bool {
	return false
}

func TestAll(t *testing.T) {
	user_id := "123"
	ip := "192.168.0.1"
	wrongIp := "192.168.0.2"
	a := auth.Auth{
		DB: fakeDb{},
	}

	access_token, refresh_token, err := a.GenerateTokens(user_id, ip)
	if err != nil {
		t.Errorf("Error on generating tokens: %s", err)
	}
	isValid := a.ValidateTokens(user_id, access_token, refresh_token, ip, errorHandlers{})
	if !isValid {
		t.Errorf("Error on validating tokens")
	}
	ipCheck := false
	a.ValidateTokens(user_id, access_token, refresh_token, wrongIp, errorHandlers{IpHandler: func() { ipCheck = true }})
	if !ipCheck {
		t.Errorf("Handler not invoked")
	}

	//auth.ValidateTokens(user_id, )
}
