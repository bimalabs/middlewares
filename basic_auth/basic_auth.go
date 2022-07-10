package basic_auth

import (
	"context"
	"net/http"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/bimalabs/framework/v4/middlewares"
)

type (
	basicAuth struct {
		validator ValidateUsernameAndPassword
	}

	ValidateUsernameAndPassword func(username string, password string) bool
)

func New(validator ValidateUsernameAndPassword) middlewares.Middleware {
	return &basicAuth{
		validator: validator,
	}
}

func (b *basicAuth) Attach(request *http.Request, response http.ResponseWriter) bool {
	ctx := context.WithValue(context.Background(), "scope", "basic_auth_middleware")
	username, password, ok := request.BasicAuth()
	if !ok {
		loggers.Logger.Error(ctx, "error parsing basic auth")
		http.Error(response, "invalid username or password", http.StatusUnauthorized)

		return true
	}

	if !b.validator(username, password) {
		loggers.Logger.Error(ctx, "invalid username or password")
		http.Error(response, "invalid username or password", http.StatusUnauthorized)

		return true
	}

	return false
}

func (b *basicAuth) Priority() int {
	return 257
}
