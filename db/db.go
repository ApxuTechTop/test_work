package db

type Saver interface {
	Save(user_id string, hashToken string)
}

type Database struct {
}

func (d Database) Save(user_id string, hashToken string) {

}
