package jwt

import (
	"context"
	"net/http"

	"github.com/goccy/go-json"

	"github.com/bimalabs/framework/v4/loggers"
	"github.com/bimalabs/framework/v4/middlewares"
	"github.com/bimalabs/framework/v4/routes"
	"google.golang.org/grpc"
)

type jwtRefresh struct {
	path          string
	secret        string
	signingMethod string
	expire        int
}

func NewJwtRefresh(path string, secret string, signingMethod string, expire int) routes.Route {
	return &jwtRefresh{
		path:          path,
		secret:        secret,
		signingMethod: signingMethod,
		expire:        expire,
	}
}

func (j *jwtRefresh) Path() string {
	return j.path
}

func (j *jwtRefresh) Method() string {
	return http.MethodPost
}

func (j *jwtRefresh) SetClient(client *grpc.ClientConn) {}

func (j *jwtRefresh) Middlewares() []middlewares.Middleware {
	return nil
}

func (j *jwtRefresh) Handle(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	ctx := context.WithValue(context.Background(), "scope", "jwt_refresh_token")
	body := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		loggers.Logger.Error(ctx, err.Error())
		http.Error(w, "token is empty", http.StatusBadRequest)

		return
	}

	token, ok := body["token"]
	if !ok {
		loggers.Logger.Error(ctx, "token is empty")
		http.Error(w, "token is empty", http.StatusBadRequest)

		return
	}

	claims, err := ValidateRefreshToken(j.secret, j.signingMethod, token)
	if err != nil {
		loggers.Logger.Error(ctx, err.Error())
		http.Error(w, "invalid token", http.StatusBadRequest)

		return
	}

	token, _ = CreateToken(j.secret, j.signingMethod, claims, j.expire)
	refreshToken, _ := CreateRefreshToken(j.secret, j.signingMethod, token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token, "refresh_token": refreshToken})
}
