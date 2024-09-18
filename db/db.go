package db

import (
	"context"
	"encoding/base64"

	"test_auth/config"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Saver interface {
	Save(user_id string, hashToken string) error
}
type Checker interface {
	Check(user_id string, refreshToken string) bool
}
type Loader interface {
	Load(user_id string) ([]string, error)
}
type Deleter interface {
	Delete(user_id string, refreshToken string) error
}

type RefreshTokenStorage interface {
	Saver
	Loader
	Deleter
}

type Database struct {
	Connection *pgxpool.Pool
}

func (d Database) Save(user_id string, hashToken string) error {
	_, err := d.Connection.Exec(context.Background(), `
		INSERT INTO refresh_tokens (user_id, refresh_token)
		VALUES ($1, $2)
	`, user_id, hashToken)
	if err != nil {
		return err
	}
	return nil
}

//	func (d Database) Check(user_id string, refreshToken string) bool {
//		tokens, _ := d.Load(user_id)
//		decodedToken, _ := base64.StdEncoding.DecodeString(refreshToken)
//		for _, hashToken := range tokens {
//			err := bcrypt.CompareHashAndPassword([]byte(hashToken), decodedToken)
//			if err == nil {
//				return true
//			}
//		}
//		return false
//	}
func (d Database) Load(user_id string) ([]string, error) {
	rows, err := d.Connection.Query(context.Background(), `
        SELECT refresh_token
        FROM refresh_tokens
        WHERE user_id = $1
    `, user_id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return tokens, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (d Database) Delete(user_id string, refreshToken string) error {
	rows, err := d.Connection.Query(context.Background(), `
        SELECT id, refresh_token
        FROM refresh_tokens
        WHERE user_id = $1
    `, user_id)
	if err != nil {
		return err
	}
	defer rows.Close()
	decoded, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return err
	}
	for rows.Next() {
		var token string
		var id int
		if err := rows.Scan(&id, &token); err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(token), decoded) == nil {
			_, err := d.Connection.Query(context.Background(), `
				DELETE
				FROM refresh_tokens
				WHERE id = $1
			`, id)
			return err
		}
	}
	return nil
}

func GetDatabase() (*Database, error) {

	pool, err := pgxpool.New(context.Background(), config.GetDatabaseURL())
	db := &Database{
		Connection: pool,
	}
	return db, err
}
