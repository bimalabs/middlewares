package api_key

import (
	"context"
	"net/http"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/bimalabs/framework/v4/middlewares"
)

const (
	LocationHeader  = "header"
	LocationQueries = "query"
)

type (
	apiKeyAuth struct {
		validator   ValidateApiKey
		keyLocation string
		keyName     string
	}

	ValidateApiKey func(apiKey string) bool
)

func New(location string, name string, key string) middlewares.Middleware {
	return &apiKeyAuth{validator: func(apiKey string) bool {
		return key == apiKey
	}, keyLocation: location, keyName: name}
}

func NewStorage(location string, name string, validator ValidateApiKey) middlewares.Middleware {
	return &apiKeyAuth{validator: validator, keyLocation: location, keyName: name}
}

func (a *apiKeyAuth) Attach(request *http.Request, response http.ResponseWriter) bool {
	ctx := context.WithValue(context.Background(), loggers.ScopeKey, "api_key_auth_middleware")
	var key string
	if a.keyLocation == LocationHeader {
		key = request.Header.Get(a.keyName)
	}

	if a.keyLocation == LocationQueries {
		key = request.URL.Query().Get(a.keyName)
	}

	if !a.validator(key) {
		loggers.Logger.Error(ctx, "invalid api key")
		http.Error(response, "invalid api key", http.StatusUnauthorized)

		return true
	}

	return false
}

func (a *apiKeyAuth) Priority() int {
	return 257
}
