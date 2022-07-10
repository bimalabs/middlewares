package jwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func Test_Validate_Jwt(t *testing.T) {
	_, err := validateToken("secret", jwt.SigningMethodHS512.Name, "invalid")
	assert.NotNil(t, err)

	claims := jwt.MapClaims{
		"id":    "test",
		"email": "test@mail.com",
		"role":  1,
	}

	token, err := createToken("secret", jwt.SigningMethodHS512.Name, claims, 2)

	assert.Nil(t, err)
	assert.NotNil(t, token)

	_, err = validateToken("secret", "invalid", token)
	assert.NotNil(t, err)

	result, err := validateToken("secret", jwt.SigningMethodHS512.Name, token)
	assert.Nil(t, err)

	assert.Equal(t, claims["id"], result["id"])
	assert.Equal(t, claims["email"], result["email"])
	assert.Equal(t, claims["role"], int(result["role"].(float64)))
}

func Test_Refresh_Jwt(t *testing.T) {
	_, err := validateRefreshToken("secret", jwt.SigningMethodHS512.Name, "invalid")
	assert.NotNil(t, err)

	claims := jwt.MapClaims{
		"id":    "test",
		"email": "test@mail.com",
		"role":  1,
	}

	token, err := createToken("secret", jwt.SigningMethodHS512.Name, claims, 2)

	refreshToken, err := createRefreshToken("secret", jwt.SigningMethodHS512.Name, token)

	assert.Nil(t, err)
	assert.NotNil(t, token)

	_, err = validateRefreshToken("secret", "invalid", refreshToken)
	assert.NotNil(t, err)

	_, err = validateRefreshToken("secret", jwt.SigningMethodHS512.Name, token)
	assert.NotNil(t, err)

	result, err := validateRefreshToken("secret", jwt.SigningMethodHS512.Name, refreshToken)
	assert.Nil(t, err)

	assert.Equal(t, claims["id"], result["id"])
	assert.Equal(t, claims["email"], result["email"])
	assert.Equal(t, claims["role"], int(result["role"].(float64)))
}
