package jwt

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// Generate your own secret key!
var secret = []byte("can-you-keep-a-secret?")

type MyJWTClaims struct {
	*jwt.RegisteredClaims
	UserInfo interface{}
}

func CreateToken(sub string, userInfo interface{}) (string, error) {
	// Get the token instance with the Signing method
	token := jwt.New(jwt.GetSigningMethod("HS256"))

	// Choose an expiration time. Shorter the better
	exp := time.Now().Add(time.Hour * 24)
	// Add your claims
	token.Claims = &MyJWTClaims{
		&jwt.RegisteredClaims{
			// Set the exp and sub claims. sub is usually the userID
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   sub,
		},
		userInfo,
	}
	// Sign the token with your secret key
	val, err := token.SignedString(secret)
	if err != nil {
		// On error return the error
		return "", err
	}
	// On success return the token string
	return val, nil
}

func GetClaimsFromToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

type claimskey int

var claimsKey claimskey

func SetJWTClaimsContext(ctx context.Context, claims jwt.MapClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func JWTClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(claimsKey).(jwt.MapClaims)
	return claims, ok
}
