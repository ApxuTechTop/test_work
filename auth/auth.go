package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"test_auth/config"
	"test_auth/db"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	DB                  db.Saver
	AccessTokenDuration time.Duration
}

type ErrorHandlers interface {
	OnId(expected string, received string) (isOk bool)
	OnExp(expected int64, received int64) (isOk bool)
	OnIp(expected string, received string) (isOk bool)
}

func (a Auth) ValidateTokens(user_id string, accessToken string, refreshToken string, requestIp string, handlers ErrorHandlers) bool {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return config.GetSecretKey(), nil
	})
	if err != nil {
		return false
	}
	id := claims["id"].(string)
	if id != user_id {
		if !handlers.OnId(id, user_id) {
			return false
		}

	}
	expirationTime := int64(claims["exp"].(float64))
	currentTime := time.Now().Unix()
	if expirationTime <= currentTime {
		if !handlers.OnExp(currentTime, expirationTime) {
			return false
		}
	}

	ip := claims["ip"].(string)
	if ip != requestIp {
		if !handlers.OnIp(ip, requestIp) {
			return false
		}
	}

	// TODO check hashToken

	return true
}

func generateRefreshToken() (refresh_token string, hash_token string, e error) {
	data := make([]byte, 64)
	_, err := rand.Read(data)
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

func generateAccessToken(user_id string, ip string, duration time.Duration) (string, error) {
	payload := jwt.MapClaims{
		"id":  user_id,
		"ip":  ip,
		"exp": time.Now().Add(duration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	signedToken, err := token.SignedString(config.GetSecretKey())
	return signedToken, err
}

func (a Auth) GenerateTokens(user_id string, ip string) (accessToken string, refreshToken string, err error) {
	accessToken, err = generateAccessToken(user_id, ip, a.AccessTokenDuration)
	if err != nil {
		return "", "", err
	}
	refreshToken, hashedToken, err := generateRefreshToken()
	if err != nil {
		return "", "", err
	}
	a.DB.Save(user_id, hashedToken)
	return accessToken, refreshToken, nil
}
