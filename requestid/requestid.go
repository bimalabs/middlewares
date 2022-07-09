package requestid

import (
	"net/http"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/google/uuid"
)

type RequestID struct {
	RequestIDHeader string
}

func (r *RequestID) Attach(request *http.Request, response http.ResponseWriter) bool {
	if loggers.Logger == nil {
		return false
	}

	requestID := request.Header.Get(r.RequestIDHeader)
	if requestID == "" {
		requestID = uuid.NewString()
	}

	response.Header().Add(r.RequestIDHeader, requestID)
	loggers.Logger.Add("request_id", requestID)

	return false
}

func (r *RequestID) Priority() int {
	return 259
}
