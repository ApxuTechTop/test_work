package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"test_auth/config"
	"test_auth/db"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	DB                  db.RefreshTokenStorage
	AccessTokenDuration time.Duration
}

type IdErrorHandler interface {
	OnId(expected string, received string) (isOk bool)
}
type ExpErrorHandler interface {
	OnExp(expected int64, received int64) (isOk bool)
}
type IpErrorHandler interface {
	OnIp(expected string, received string) (isOk bool)
}
type WrongSignatureHandler interface {
	OnWrongSignature(expected []byte, received []byte) (isOk bool)
}

type MissingRefreshTokenErrorHandler interface {
	OnMissingRefreshToken(received string) (isOk bool)
}

type ErrorHandlers interface {
	IdErrorHandler
	ExpErrorHandler
	IpErrorHandler
	WrongSignatureHandler
	MissingRefreshTokenErrorHandler
}

func (a Auth) ValidateTokens(user_id string, accessToken string, refreshToken string, requestIp string, handlers ErrorHandlers) bool {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return config.GetSecretKey(), nil
	})
	isOk := true
	if err != nil {
		isOk = false
	}
	id := claims["id"].(string)
	if id != user_id && !handlers.OnId(id, user_id) {
		isOk = false
	}
	expirationTime := int64(claims["exp"].(float64))
	currentTime := time.Now().Unix()
	if expirationTime <= currentTime && !handlers.OnExp(currentTime, expirationTime) {
		isOk = false
	}

	ip := claims["ip"].(string)
	if ip != requestIp && !handlers.OnIp(ip, requestIp) {
		isOk = false
	}

	// TODO check hashToken
	signature := token.Signature
	data, _ := base64.StdEncoding.DecodeString(refreshToken)
	sigBytes := []byte(signature[:32])
	if !bytes.HasPrefix(data, sigBytes) && !handlers.OnWrongSignature(data[:32], sigBytes) {
		isOk = false
	}
	if !a.DB.Check(user_id, refreshToken) && !handlers.OnMissingRefreshToken(refreshToken) {
		isOk = false
	}

	return isOk
}

func generateRefreshToken(signature string) (refresh_token string, hash_token string, e error) {
	data := make([]byte, 64)
	// if len(signature) > len(data) {
	// 	return "", "", fmt.Errorf("signature is too long")
	// }
	_, err := rand.Read(data)
	copy(data, []byte(signature[:32]))
	if err != nil {
		return "", "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(data)
	hashToken, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return refreshToken, string(hashToken), nil
}

func generateAccessToken(user_id string, ip string, duration time.Duration) (string, string, error) {
	salt := make([]byte, 16) // 16 байт соли
	_, err := rand.Read(salt)
	payload := jwt.MapClaims{
		"id":   user_id,
		"ip":   ip,
		"exp":  time.Now().Add(duration).Unix(),
		"salt": base64.StdEncoding.EncodeToString(salt),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	signedToken, err := token.SignedString(config.GetSecretKey())
	if err != nil {
		return "", "", err
	}
	tokenSignature := signedToken[strings.LastIndex(signedToken, ".")+1:]
	return signedToken, tokenSignature, err
}

func (a Auth) GenerateTokens(user_id string, ip string) (accessToken string, refreshToken string, err error) {
	accessToken, signature, err := generateAccessToken(user_id, ip, a.AccessTokenDuration)
	if err != nil {
		return "", "", err
	}
	refreshToken, hashedToken, err := generateRefreshToken(signature)
	if err != nil {
		return "", "", err
	}
	a.DB.Save(user_id, hashedToken)
	return accessToken, refreshToken, nil
}
