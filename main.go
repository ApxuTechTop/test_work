package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"test_auth/auth"
	"test_auth/db"
)

func sendMailWarn() {

}

var a auth.Auth = auth.Auth{
	DB:                  db.Database{},
	AccessTokenDuration: time.Minute * 1,
}

func getTokensHandler(w http.ResponseWriter, r *http.Request) {

	values := r.URL.Query()
	if len(values["user_id"]) <= 0 {
		fmt.Fprintf(w, "Hello anon")
		return
	}
	user_id := values["user_id"][0]
	w.Header().Set("Content-Type", "application/json")
	//fmt.Fprintf(w, "hello %s from %s | %s", user_id, r.Host, r.URL.Path)
	accessToken, refreshToken, err := a.GenerateTokens(user_id, r.RemoteAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	tokens := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	jsonResponse, _ := json.Marshal(tokens)
	w.Write(jsonResponse)
}

type errorHandlers struct{}

func (e errorHandlers) OnWrongIp(expected string, received string) bool {
	sendMailWarn()
	return true
}
func (e errorHandlers) OnWrongExp(expected int64, received int64) bool {
	return false
}
func (e errorHandlers) OnWrongId(expected string, received string) bool {
	return false
}
func (e errorHandlers) OnWrongSignature(expected []byte, received []byte) bool {
	return false
}
func (e errorHandlers) OnMissingRefreshToken(received string) bool {
	return false
}

func refreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if len(values["user_id"]) <= 0 {
		fmt.Fprintf(w, "No parameter user_id")
		return
	}
	user_id := values["user_id"][0]
	ip := r.RemoteAddr

	decoder := json.NewDecoder(r.Body)
	tokens := make(map[string]string)
	decoder.Decode(&tokens)
	accessToken := tokens["access_token"]
	refreshToken := tokens["refresh_token"]

	//refreshTokens(user_id, accessToken, refreshToken, ip)
	isValid := a.ValidateTokens(user_id, accessToken, refreshToken, ip, errorHandlers{})
	if !isValid {
		fmt.Fprint(w, "Not valid tokens")
		return
	}
	newAccessToken, newRefreshToken, err := a.GenerateTokens(user_id, ip)
	if err != nil {
		fmt.Fprint(w, err)
		return
	}
	newTokens := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}

	jsonResponse, _ := json.Marshal(newTokens)
	w.Write(jsonResponse)
	// if ip != info.ip // warning
	// else refresh access token time
}

func main() {
	fmt.Println("hello world")
	http.HandleFunc("/get-tokens", getTokensHandler)
	http.HandleFunc("/refresh-token", refreshTokensHandler)
	err := http.ListenAndServe("0.0.0.0:80", nil)
	if err != nil {
		fmt.Println(err)
	}
}
