package test

import (
	"encoding/base64"
	"fmt"
	"test_auth/auth"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type DbMock struct {
	storage map[string][]string
}

func (d *DbMock) Save(user_id string, hashToken string) {
	d.storage[user_id] = append(d.storage[user_id], hashToken)
}
func (d *DbMock) Check(user_id string, refreshToken string) bool {
	decodedToken, _ := base64.StdEncoding.DecodeString(refreshToken)
	for _, hashToken := range d.storage[user_id] {
		err := bcrypt.CompareHashAndPassword([]byte(hashToken), decodedToken)
		if err == nil {
			return true
		}
	}

	return false
}

type errorHandlers struct {
	IpHandler func()
}

func (e errorHandlers) OnWrongIp(expected string, received string) bool {
	e.IpHandler()
	fmt.Printf("ip %s %s\n", expected, received)
	return true
}
func (e errorHandlers) OnWrongExp(expected int64, received int64) bool {
	fmt.Printf("exp %d %d\n", expected, received)
	return false
}
func (e errorHandlers) OnWrongId(expected string, received string) bool {
	fmt.Printf("id %s %s\n", expected, received)
	return false
}
func (e errorHandlers) OnWrongSignature(expected []byte, received []byte) bool {
	fmt.Printf("sign %s %s\n", expected, received)
	return false
}
func (e errorHandlers) OnMissingRefreshToken(received string) bool {
	fmt.Printf("refresh %s\n", received)
	return false
}

func TestAll(t *testing.T) {
	user_id := "123"
	ip := "192.168.0.1"
	wrongIp := "192.168.0.2"
	a := auth.Auth{
		DB: &DbMock{
			storage: map[string][]string{},
		},
		AccessTokenDuration: time.Minute,
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
	new_access_token, new_refresh_token, err := a.GenerateTokens(user_id, ip)
	if err != nil {
		t.Errorf("Error on generating tokens: %s", err)
	}

	if a.ValidateTokens(user_id, access_token, new_refresh_token, ip, errorHandlers{}) {
		t.Errorf("Error on comparing refresh token")
	}
	if !a.ValidateTokens(user_id, new_access_token, new_refresh_token, ip, errorHandlers{}) {
		t.Errorf("Expected valid tokens")
	}

	//auth.ValidateTokens(user_id, )
}
