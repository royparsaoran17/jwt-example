package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"jwt-example/entity"
	"jwt-example/jwt"
	"jwt-example/middleware"
	"log"
	"net/http"
)

func main() {

	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		var userLogin entity.UserLogin

		if err := json.NewDecoder(r.Body).Decode(&userLogin); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Create user if your conditions match. Below, all username and passwords are accepted.
		user := &entity.User{
			ID:       "2332-abcd-acdf-ccd2",
			Name:     "JWT Master",
			Username: userLogin.Username,
			Password: userLogin.Password,
		}

		tokenString, err := jwt.CreateToken(user.ID, user)
		fmt.Println(err, "")

		payload := make(map[string]string)
		payload["access_token"] = tokenString

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(payload)
	}

	protectedHandler := func(w http.ResponseWriter, r *http.Request) {
		claims, _ := jwt.JWTClaimsFromContext(r.Context())

		//Do something with the UserInfo claims
		if val, ok := claims["UserInfo"]; ok {
			userinfo := val.(map[string]interface{})
			fmt.Print(userinfo)
		}

		//Do something with the sub claim

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(claims)
	}

	indexHandler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Status OK")
	}

	m := mux.NewRouter()
	m.HandleFunc("/liveness", indexHandler).Methods("GET")
	m.HandleFunc("/login", loginHandler).Methods("POST")

	protected := m.PathPrefix("/").Subrouter()
	protected.Use(middleware.AuthenticationMW)
	protected.HandleFunc("/resource", protectedHandler).Methods("GET", "POST")

	log.Fatal(http.ListenAndServe(":8090", m))
}
