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

type apiKeyAuth struct {
	key         string
	keyLocation string
	keyName     string
}

func New(location string, name string, key string) middlewares.Middleware {
	return &apiKeyAuth{key: key, keyLocation: location, keyName: name}
}

func (a *apiKeyAuth) Attach(request *http.Request, response http.ResponseWriter) bool {
	ctx := context.WithValue(context.Background(), "scope", "api_key_auth_middleware")
	var key string
	if a.keyLocation == LocationHeader {
		key = request.Header.Get(a.keyName)
	}

	if a.keyLocation == LocationQueries {
		key = request.URL.Query().Get(a.keyName)
	}

	if key != a.key {
		loggers.Logger.Error(ctx, "invalid api key")
		http.Error(response, "invalid api key", http.StatusUnauthorized)

		return true
	}

	return false
}

func (a *apiKeyAuth) Priority() int {
	return 257
}
