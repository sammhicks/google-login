package login

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type keyStore struct {
	keys   map[string]*rsa.PublicKey
	expiry time.Time
	mux    sync.Mutex
}

type jwkKey struct {
	Kty string
	Alg string
	Use string
	Kid string
	N   string
	E   string
}

type jwkKeys struct {
	Keys []jwkKey
}

func (ks *keyStore) fetchKeys() (err error) {
	if len(ks.keys) > 0 && ks.expiry.After(time.Now()) {
		log.Println("Keys still active")
		return nil
	}

	var r *http.Response

	if r, err = http.Get("https://www.googleapis.com/oauth2/v3/certs"); err != nil {
		return
	}

	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)

	var keys jwkKeys

	if err = decoder.Decode(&keys); err != nil {
		return
	}

	var expiry time.Time

	if expiry, err = time.Parse("Mon, 02 Jan 2006 15:04:05 MST", r.Header.Get("expires")); err != nil {
		return
	}

	newKeys := make(map[string]*rsa.PublicKey)

	for _, key := range keys.Keys {
		if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
			log.Printf("Key %v not a signing RSA 256 Key (%v/%v/%v)\n", key.Kid, key.Kty, key.Alg, key.Use)
			continue
		}

		var nBytes, eBytes []byte

		nBytes, err = base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return
		}

		eBytes, err = base64.RawURLEncoding.DecodeString(key.E)

		if err != nil {
			return
		}

		var n, e big.Int

		n.SetBytes(nBytes)
		e.SetBytes(eBytes)

		newKeys[key.Kid] = &rsa.PublicKey{
			N: &n,
			E: int(e.Int64()),
		}
	}

	log.Println("New keys, expiring at ", expiry)

	ks.keys = newKeys
	ks.expiry = expiry

	return nil
}

func (ks *keyStore) lookupKey(id string) (key *rsa.PublicKey, err error) {
	ks.mux.Lock()
	defer ks.mux.Unlock()

	if err = ks.fetchKeys(); err != nil {
		return
	}

	var keyFound bool

	if key, keyFound = ks.keys[id]; !keyFound {
		err = fmt.Errorf("Key \"%v\" not found", id)
		return
	}

	return
}
