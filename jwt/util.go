package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func validateToken(secret string, signing string, bearerToken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok || method != jwt.GetSigningMethod(signing) {
			return nil, errors.New("invalid token")
		}

		return []byte(secret), nil
	})

	if err != nil {
		return jwt.MapClaims{}, err
	}

	return token.Claims.(jwt.MapClaims), err
}

func createToken(secret string, method string, claims jwt.MapClaims, expire int) (string, error) {
	token := jwt.New(jwt.GetSigningMethod(method))

	claims["exp"] = time.Now().Add(time.Hour * time.Duration(expire)).Unix()
	token.Claims = claims

	return token.SignedString([]byte(secret))
}

func createRefreshToken(secret string, method string, token string) (string, error) {
	claims := jwt.MapClaims{}
	claims["token"] = token

	return createToken(secret, method, claims, 730)
}

func validateRefreshToken(secret string, method string, tokenString string) (jwt.MapClaims, error) {
	claims, err := validateToken(secret, method, tokenString)
	if err != nil {
		return jwt.MapClaims{}, err
	}

	token, ok := claims["token"]
	if !ok {
		return jwt.MapClaims{}, errors.New("invalid token")
	}

	return validateToken(secret, method, token.(string))
}
