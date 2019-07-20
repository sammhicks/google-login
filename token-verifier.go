package login

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type tokenHeader struct {
	Alg string
	Kid string
}

type tokenBody struct {
	Aud   string
	Email string
	Exp   int64
	IAt   int64
	Iss   string
	Sub   string
}

const tokenSeparator = "."

// TokenVerifier verifies Google Login Tokens
type TokenVerifier struct {
	store *keyStore
	aud   string
}

// NewTokenVerifier creates a new TokenVerifier with a given audience
func NewTokenVerifier(aud string) *TokenVerifier {
	return &TokenVerifier{
		store: &keyStore{},
		aud:   aud,
	}
}

// VerifyToken verified the given token
func (tv *TokenVerifier) VerifyToken(token string) (id string, email string, err error) {
	sections := strings.Split(token, tokenSeparator)

	if len(sections) != 3 {
		err = errors.New("token does not contain header, body, and signiature")
		return
	}

	var headerBytes []byte

	if headerBytes, err = base64.RawURLEncoding.DecodeString(sections[0]); err != nil {
		return
	}

	var header tokenHeader

	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return
	}

	if header.Alg != "RS256" {
		err = fmt.Errorf("algorithm \"%v\" is not supported", header.Alg)
		return
	}

	var key *rsa.PublicKey

	if key, err = tv.store.lookupKey(header.Kid); err != nil {
		return
	}

	hash := sha256.New()
	hash.Write([]byte(sections[0]))
	hash.Write([]byte(tokenSeparator))
	hash.Write([]byte(sections[1]))

	hashedPayload := hash.Sum(nil)

	var signiatureBytes []byte

	if signiatureBytes, err = base64.RawURLEncoding.DecodeString(sections[2]); err != nil {
		return
	}

	if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hashedPayload[:], signiatureBytes); err != nil {
		return
	}

	var bodyBytes []byte

	if bodyBytes, err = base64.RawURLEncoding.DecodeString(sections[1]); err != nil {
		return
	}

	var body tokenBody

	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return
	}

	if body.Aud != tv.aud {
		err = errors.New("aud wrong")
		return
	}

	if body.Iss != "accounts.google.com" && body.Iss != "https://accounts.google.com" {
		err = errors.New("iss wrong")
		return
	}

	if time.Now().Before(time.Unix(body.IAt, 0)) {
		err = errors.New("issued in the past")
		return
	}

	if time.Now().After(time.Unix(body.Exp, 0)) {
		err = errors.New("expired")
		return
	}

	id = body.Sub

	email = body.Email

	return
}
