package jwt

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/bimalabs/framework/v4/configs"
	"github.com/bimalabs/framework/v4/loggers"
	"github.com/bimalabs/framework/v4/middlewares"
)

type middleware struct {
	debug         bool
	secret        string
	signingMethod string
	whitelist     string
	env           *configs.Env
}

func NewJwt(env *configs.Env, signingMethod string, whitelist string) middlewares.Middleware {
	return &middleware{
		debug:         env.Debug,
		secret:        env.Secret,
		env:           env,
		signingMethod: signingMethod,
		whitelist:     whitelist,
	}
}

func (j *middleware) Attach(request *http.Request, response http.ResponseWriter) bool {
	ctx := context.WithValue(context.Background(), "scope", "jwt_middleware")
	match, _ := regexp.MatchString(j.whitelist, request.RequestURI)
	if match {
		if j.debug {
			var log strings.Builder
			log.WriteString("whitelisting url ")
			log.WriteString(request.RequestURI)

			loggers.Logger.Debug(ctx, log.String())
		}

		return false
	}

	bearerToken := strings.Split(request.Header.Get("Authorization"), " ")
	if len(bearerToken) != 2 {
		loggers.Logger.Error(ctx, "token not provided")
		http.Error(response, "unauthorization", http.StatusUnauthorized)

		return true
	}

	claims, err := ValidateToken(j.secret, j.signingMethod, strings.TrimSpace(bearerToken[1]))
	if err != nil {
		loggers.Logger.Error(ctx, err.Error())
		http.Error(response, "unauthorization", http.StatusUnauthorized)

		return true
	}

	if user, ok := claims["user"]; ok {
		j.env.User = user.(string)
		request.Header.Add("X-Bima-User", j.env.User)

		return false
	}

	loggers.Logger.Error(ctx, "user not provided")
	http.Error(response, "unauthorization", http.StatusUnauthorized)

	return true
}

func (j *middleware) Priority() int {
	return 257
}
