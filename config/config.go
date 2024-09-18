package config

import "os"

var jwtSecretKey = []byte("very-secret-key")

func GetSecretKey() []byte {
	return jwtSecretKey
}

func GetDatabaseURL() string {
	return os.Getenv("DATABASE_URL")
}
