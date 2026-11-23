package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
)

const (
	_UserDataPrefix  = "Sequence"
	_UserDataVersion = 1

	_UserDataVersionBoundHeader = 2
)

type userData struct {
	Prefix  string
	Version int
	Hash    []byte
}

func (u *userData) String() string {
	return fmt.Sprintf("%s/%d:%s", u.Prefix, u.Version, base64.StdEncoding.EncodeToString(u.Hash))
}

func generateUserData(r *http.Request, reqBody []byte, resBody []byte, boundHeader string) ([]byte, error) {
	version := _UserDataVersion
	hasher := sha256.New()
	hasher.Write([]byte(r.Method + " " + r.URL.Path + "\n"))
	if boundHeader != "" {
		version = _UserDataVersionBoundHeader
		hasher.Write([]byte(r.Header.Get(boundHeader) + "\n"))
	}
	hasher.Write(reqBody)
	hasher.Write([]byte("\n"))
	hasher.Write(resBody)
	hash := hasher.Sum(nil)

	userData := &userData{
		Prefix:  _UserDataPrefix,
		Version: version,
		Hash:    hash,
	}
	return []byte(userData.String()), nil
}
