package config

var jwtSecretKey = []byte("very-secret-key")

func GetSecretKey() []byte {
	return jwtSecretKey
}
