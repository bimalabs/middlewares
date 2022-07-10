package requestid

import (
	"net/http"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/bimalabs/framework/v4/middlewares"
	"github.com/google/uuid"
)

type requestID struct {
	header string
}

func New(header string) middlewares.Middleware {
	return &requestID{
		header: header,
	}
}

func (r *requestID) Attach(request *http.Request, response http.ResponseWriter) bool {
	if loggers.Logger == nil {
		return false
	}

	requestID := request.Header.Get(r.header)
	if requestID == "" {
		requestID = uuid.NewString()
	}

	response.Header().Add(r.header, requestID)
	loggers.Logger.Add("request_id", requestID)

	return false
}

func (r *requestID) Priority() int {
	return 259
}
