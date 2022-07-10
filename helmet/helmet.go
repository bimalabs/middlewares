package helmet

import (
	"net/http"

	"github.com/bimalabs/framework/v4/middlewares"
	"github.com/goddtriffin/helmet"
)

type middleware struct {
}

func New() middlewares.Middleware {
	return &middleware{}
}

func (h *middleware) Attach(_ *http.Request, response http.ResponseWriter) bool {
	helmet := helmet.Default()

	helmet.ContentSecurityPolicy.Header(response)
	helmet.XContentTypeOptions.Header(response)
	helmet.XDNSPrefetchControl.Header(response)
	helmet.XDownloadOptions.Header(response)
	helmet.ExpectCT.Header(response)
	helmet.FeaturePolicy.Header(response)
	helmet.XFrameOptions.Header(response)
	helmet.XPermittedCrossDomainPolicies.Header(response)
	helmet.XPoweredBy.Header(response)
	helmet.ReferrerPolicy.Header(response)
	helmet.StrictTransportSecurity.Header(response)
	helmet.XXSSProtection.Header(response)

	return false
}

func (h *middleware) Priority() int {
	return -255
}
