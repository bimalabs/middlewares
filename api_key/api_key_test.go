package api_key

import (
	"net/http/httptest"
	"testing"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/stretchr/testify/assert"
)

func Test_Api_Key(t *testing.T) {
	loggers.Default("test")
	middleware := apiKeyAuth{
		key:         "test",
		keyLocation: LocationQueries,
		keyName:     "api",
	}

	req := httptest.NewRequest("POST", "http://bima.framework/foo", nil)
	w := httptest.NewRecorder()

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, true, middleware.Attach(req, w))

	middleware = apiKeyAuth{
		key:         "test",
		keyLocation: LocationQueries,
		keyName:     "api",
	}

	req = httptest.NewRequest("GET", "http://bima.framework/foo?api=xxx", nil)
	w = httptest.NewRecorder()

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, true, middleware.Attach(req, w))

	middleware = apiKeyAuth{
		key:         "test",
		keyLocation: LocationQueries,
		keyName:     "api",
	}

	req = httptest.NewRequest("GET", "http://bima.framework/foo?api=test", nil)
	w = httptest.NewRecorder()

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, false, middleware.Attach(req, w))

	middleware = apiKeyAuth{
		key:         "test",
		keyLocation: LocationHeader,
		keyName:     "Api-Key",
	}

	req = httptest.NewRequest("GET", "http://bima.framework/foo", nil)
	w = httptest.NewRecorder()
	req.Header.Add("Api-Key", "test")

	assert.Equal(t, 257, middleware.Priority())
	assert.Equal(t, false, middleware.Attach(req, w))
}
