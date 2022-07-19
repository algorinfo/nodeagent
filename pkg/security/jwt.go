package security

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JWTConfig struct {
	Private    string
	Public     string
	Alg        string
	Issuer     string
	Audience   string
	DefaultExp int64
}

type JWT struct {
	Opts    *JWTConfig
	public  []byte
	private []byte
	method  jwt.SigningMethod
}

func (j *JWT) Open() error {
	pkey, err := os.ReadFile(j.Opts.Public)
	if err != nil {
		return err
	}
	j.public = pkey
	privkey, err := os.ReadFile(j.Opts.Private)
	if err != nil {
		return err
	}
	j.private = privkey

	j.method = jwt.GetSigningMethod(j.Opts.Alg)

	return nil

}

func (j *JWT) verify(at string, key interface{}) error {
	parts := strings.Split(at, ".")
	err := j.method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
	if err != nil {
		return err
	}
	return nil
}

// Verify verifies if a token is valid and return it decoded
func (j *JWT) Verify(at string) (*jwt.Token, error) {
	// tokData := regexp.MustCompile(`\s*$`).ReplaceAll(at, []byte{})
	token, err := jwt.Parse(at, func(t *jwt.Token) (interface{}, error) {
		if j.isEs() {
			return jwt.ParseECPublicKeyFromPEM(j.public)
		} else if j.isRs() {
			return jwt.ParseRSAPublicKeyFromPEM(j.public)
		} else if j.isEd() {
			return jwt.ParseEdPublicKeyFromPEM(j.public)
		}
		return []byte{}, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// defaultClaims define the defaults claims
func (j *JWT) defaultClaims() jwt.MapClaims {
	claims := make(jwt.MapClaims)
	now := time.Now().Unix()
	claims["exp"] = now + (60 * j.Opts.DefaultExp)
	claims["iat"] = now
	if j.Opts.Audience != "" {
		claims["aud"] = j.Opts.Audience
	}
	if j.Opts.Issuer != "" {
		claims["iss"] = j.Opts.Issuer
	}
	return claims
}

// Sign Sign a Map
func (j *JWT) Sign(body map[string]interface{}) (*string, error) {
	claims := j.defaultClaims()
	var key interface{}
	var err error
	for k, v := range body {
		claims[k] = v
	}
	token := jwt.NewWithClaims(j.method, claims)
	if j.isEs() {
		key, err = jwt.ParseECPrivateKeyFromPEM(j.private)
		if err != nil {
			return nil, err
		}
	} else if j.isRs() {
		key, err = jwt.ParseRSAPrivateKeyFromPEM(j.private)
		if err != nil {
			return nil, err
		}
	} else if j.isEd() {
		key, err = jwt.ParseEdPrivateKeyFromPEM(j.private)
		if err != nil {
			return nil, err
		}
	}

	out, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("Error signing token: %v", err)
	}
	return &out, nil
}

func (j *JWT) Show(t string) (*jwt.Token, error) {
	data, err := jwt.Parse(t, nil)
	if data == nil {
		return nil, err
	}
	return data, nil
}

func (j *JWT) isEs() bool {
	return strings.HasPrefix(j.Opts.Alg, "ES")
}

func (j *JWT) isRs() bool {
	return strings.HasPrefix(j.Opts.Alg, "RS") || strings.HasPrefix(j.Opts.Alg, "PS")
}

func (j *JWT) isEd() bool {
	return strings.HasPrefix(strings.ToUpper(j.Opts.Alg), "Ed")
}

func loadData(p string) ([]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("No path specified")
	}

	var rdr io.Reader
	if p == "-" {
		rdr = os.Stdin
	} else if p == "+" {
		return []byte("{}"), nil
	} else {
		if f, err := os.Open(p); err == nil {
			rdr = f
			defer f.Close()
		} else {
			return nil, err
		}
	}
	return ioutil.ReadAll(rdr)
}
