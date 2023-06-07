package middleware

import (
	"fmt"
	"jwt-example/jwt"
	"net/http"
	"strings"
)

func AuthenticationMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth_header := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth_header, "Bearer") {
			http.Error(w, "Not Authorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(auth_header, "Bearer ")

		fmt.Println(tokenString)
		claims, err := jwt.GetClaimsFromToken(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		r = r.WithContext(jwt.SetJWTClaimsContext(r.Context(), claims))
		next.ServeHTTP(w, r)
	})
}
