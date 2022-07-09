package requestid

import (
	"net/http/httptest"
	"testing"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/stretchr/testify/assert"
)

func Test_RequestIDHeader_Without_Logger(t *testing.T) {
	middleware := RequestID{
		RequestIDHeader: "X-Request-ID",
	}

	req := httptest.NewRequest("GET", "http://bima.framework/foo", nil)
	w := httptest.NewRecorder()

	assert.Equal(t, 259, middleware.Priority())
	assert.Equal(t, false, middleware.Attach(req, w))
}

func Test_RequestIDHeader_With_Logger(t *testing.T) {
	middleware := RequestID{
		RequestIDHeader: "X-Request-ID",
	}

	loggers.Default("test")

	req := httptest.NewRequest("GET", "http://bima.framework/foo", nil)
	w := httptest.NewRecorder()

	assert.Equal(t, 259, middleware.Priority())
	assert.Equal(t, false, middleware.Attach(req, w))
}
