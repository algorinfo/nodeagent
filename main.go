package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/algorinfo/nodeagent/internal/utils"
	"github.com/algorinfo/nodeagent/pkg/security"
)

var (
	jwtPrivate = os.Getenv("NA_JWT_PRIV")
	jwtPublic  = os.Getenv("NA_JWT_PUB")
	jwtAlg     = utils.Env("NA_JWT_ALG", "ES512")
	// RFC 7519 fields
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
	jwtIssuer     = utils.Env("NA_JWT_ISS", "")
	jwtAudience   = utils.Env("NA_JWT_AUD", "")
	jwtDefaultExp = utils.Env("NA_JWT_EXP", "30")
	Version       = "dev"
	Commit        = "dev"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	defaultExp, _ := strconv.ParseInt(jwtDefaultExp, 10, 64)
	// commands
	jwtCmd := flag.NewFlagSet("jwt", flag.ExitOnError)
	flagSign := jwtCmd.Bool("sign", false, "sign data")
	flagVerify := jwtCmd.String("verify", "", "verify a jwt token")
	flagShow := jwtCmd.String("show", "", "decode and print the jwt token")
	flagExp := jwtCmd.Int64("exp", defaultExp, "Default expiration time for a token")
	flagClaims := make(utils.ArgList)

	// Params
	// user := jwtCmd.String("user", "nuxion", "User to encode")
	jwtCmd.Var(flagClaims, "claim", "add additional claims. may be used more than once")
	jwtCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  One of the following flags is required: sign, verify\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	switch os.Args[1] {
	case "jwt":
		err := jwtCmd.Parse(os.Args[2:])

		jwtcli := security.JWT{Opts: &security.JWTConfig{
			Private:    jwtPrivate,
			Public:     jwtPublic,
			Alg:        jwtAlg,
			Issuer:     jwtIssuer,
			Audience:   jwtAudience,
			DefaultExp: *flagExp,
		}}

		err = jwtcli.Open()
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(2)
		}

		// token := os.Getenv("ACCESS")
		if *flagVerify != "" {
			_, err = jwtcli.Verify(*flagVerify)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Token ok")
			}

		} else if *flagSign {
			body := make(map[string]interface{})
			if len(flagClaims) > 0 {
				for k, v := range flagClaims {
					body[k] = v
				}
			}
			encoded, err := jwtcli.Sign(body)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(*encoded)
		} else if *flagShow != "" {
			decoded, err := jwtcli.Show(*flagShow)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Header: ")
			utils.PrintJSON(decoded.Header)

			fmt.Println("Claims: ")
			utils.PrintJSON(decoded.Claims)

		} else {
			flag.Usage()
			fmt.Println("None of the required flags are present.  What do you want me to do?")
		}

	}
}
