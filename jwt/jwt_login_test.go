package jwt

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func Test_Jwt_Login_Invalid_Payload(t *testing.T) {
	loggers.Default("test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	endpoint := "0.0.0.0:111"
	conn, _ := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))

	route := DefaultJwtLogin("/login", "secret", jwt.SigningMethodHS512.Name, false, FindUserByUsernameAndPassword(func(username, password string) jwt.MapClaims {
		return jwt.MapClaims{
			"id": "test",
		}
	}))
	route.SetClient(conn)

	req := httptest.NewRequest("POST", "http://bima.framework/login", nil)
	w := httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp := w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	payload := map[string]string{
		"username": "test",
	}
	body, _ := json.Marshal(payload)

	req = httptest.NewRequest("POST", "http://bima.framework/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp = w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	payload = map[string]string{}
	body, _ = json.Marshal(payload)

	req = httptest.NewRequest("POST", "http://bima.framework/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp = w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	payload = map[string]string{
		"username": "test",
		"password": "test",
	}
	body, _ = json.Marshal(payload)

	req = httptest.NewRequest("POST", "http://bima.framework/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp = w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func Test_Jwt_Login_Valid_Payload(t *testing.T) {
	loggers.Default("test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	endpoint := "0.0.0.0:111"
	conn, _ := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))

	route := DefaultJwtLogin("/login", "secret", jwt.SigningMethodHS512.Name, false, FindUserByUsernameAndPassword(func(username, password string) jwt.MapClaims {
		return jwt.MapClaims{
			"user": "test",
		}
	}))
	route.SetClient(conn)

	payload := map[string]string{
		"username": "test",
		"password": "test",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "http://bima.framework/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp := w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	route = DefaultJwtLogin("/login", "secret", jwt.SigningMethodHS512.Name, true, FindUserByUsernameAndPassword(func(username, password string) jwt.MapClaims {
		return jwt.MapClaims{
			"user": "test",
		}
	}))
	route.SetClient(conn)

	payload = map[string]string{
		"username": "test",
		"password": "test",
	}
	body, _ = json.Marshal(payload)

	req = httptest.NewRequest("POST", "http://bima.framework/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	route.Handle(w, req, map[string]string{})

	resp = w.Result()

	assert.Equal(t, http.MethodPost, route.Method())
	assert.Equal(t, "/login", route.Path())
	assert.Nil(t, route.Middlewares())
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
