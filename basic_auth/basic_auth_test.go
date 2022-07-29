package basic_auth

import (
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/stretchr/testify/assert"
)

func Test_Basic_Auth(t *testing.T) {
	loggers.Default("test")
	middleware := basicAuth{
		validator: func(username, password string) bool {
			return false
		},
	}

	req := httptest.NewRequest("POST", "http://bima.framework/foo", nil)
	w := httptest.NewRecorder()

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, true, middleware.Attach(req, w))

	token := base64.StdEncoding.EncodeToString([]byte("xxx"))
	middleware = basicAuth{
		validator: func(username, password string) bool {
			return false
		},
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "http://bima.framework/foo", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", token))

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, true, middleware.Attach(req, w))

	token = base64.StdEncoding.EncodeToString([]byte("bima:bima"))
	middleware = basicAuth{
		validator: func(username, password string) bool {
			return false
		},
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "http://bima.framework/foo", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", token))

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, true, middleware.Attach(req, w))

	middleware = basicAuth{
		validator: func(username, password string) bool {
			return true
		},
	}

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, false, middleware.Attach(req, w))
}
