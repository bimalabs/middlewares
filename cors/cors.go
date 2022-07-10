package cors

import (
	"net/http"

	"github.com/bimalabs/framework/v4/middlewares"
	"github.com/rs/cors"
)

type middleware struct {
	options cors.Options
}

func New(options cors.Options) middlewares.Middleware {
	return &middleware{
		options: options,
	}
}

func (c *middleware) Attach(request *http.Request, response http.ResponseWriter) bool {
	handler := cors.New(c.options)
	handler.HandlerFunc(response, request)

	return false
}

func (c *middleware) Priority() int {
	return -255
}
