package entity

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type UserLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
