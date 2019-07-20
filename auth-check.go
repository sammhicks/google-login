package login

import (
	"context"
	"log"
	"net/http"
)

// UserAuth is the information about an authenticated user
type UserAuth struct {
	ID    string
	Email string
}

type userAuthKeyType string

const userAuthKey userAuthKeyType = "userAuth"

// WithAuthCheck wraps a Handler with a user authentication check
func WithAuthCheck(tv *TokenVerifier, inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if token == "" {
			http.Error(w, "No Auth Token", http.StatusForbidden)
			return
		}

		id, email, err := tv.VerifyToken(token)

		if err != nil {
			log.Println("Auth Error: ", err)

			http.Error(w, "Invalid Auth Token", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), userAuthKey, &UserAuth{
			ID:    id,
			Email: email,
		})

		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetAuth gets the UserAuth from a request
func GetAuth(r *http.Request) *UserAuth {
	return r.Context().Value(userAuthKey).(*UserAuth)
}
