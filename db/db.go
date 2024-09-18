package db

type Saver interface {
	Save(user_id string, hashToken string)
}
type Checker interface {
	Check(user_id string, refreshToken string) bool
}
type RefreshTokenStorage interface {
	Saver
	Checker
}

type Database struct {
}

func (d Database) Save(user_id string, hashToken string) {

}
func (d Database) Check(user_id string, refreshToken string) bool {

	return false
}
