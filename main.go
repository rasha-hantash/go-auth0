package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	// "os"

	// "github.com/codegangsta/negroni"
	// "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// print out username and password
	fmt.Println("Congrats user logged in")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Congrats user logged in\n"))
}

func RequestHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Congrats new user registered")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Congrats new user registered\n"))
}

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// main.go

// ValidateJWTHandler validates the JWT token to then be used to look up guacd connections and logging
func ValidateJWTMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// TODO refactor this in config file
		viper.SetConfigFile(".env")
		viper.ReadInConfig()
		err := viper.ReadInConfig()
		authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
		tokenString := authHeaderParts[1]

		token, err := jwt.Parse(tokenString, validateByPEMCert)
		if err != nil {
			fmt.Errorf("%v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// TODO figure out how to make this piece of code work
		// parts := strings.Split(tokenString, ".")
		// err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], token)
		// if err != nil {
		// 	fmt.Println("parts")
		// 	log.Fatal(err)
		// 	fmt.Errorf("%v", err)
		// 	w.WriteHeader(http.StatusUnauthorized)
		// 	return
		// }

		_, err = checkJWT(viper.GetString("AUTH0_AUDIENCE"), viper.GetString("AUTH0_URL"), token)
		if err != nil {
			fmt.Println(err)
			fmt.Errorf("%v", err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateByPEMCert(token *jwt.Token) (interface{}, error) {
	// TODO refactor to config
	viper.SetConfigFile(".env")
	viper.ReadInConfig()
	err := viper.ReadInConfig()
	if err != nil {
		// TODO" rather than Fatalf (which will bring the entire application down), just log it
		// TODO: return after every error
		log.Fatalf("Error while reading config file %s", err)
		return nil, err
	}
	cert := ""

	resp, err := http.Get(viper.GetString("AUTH0_URL") + ".well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	// TODO figure out why  returning this rather than just "cert,nil" this fixes the "key is invalid type" error
	return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
}

func checkJWT(audience, issuer string, token *jwt.Token) (jwt.MapClaims, error) {
	if !token.Valid {
		// TODO log this instead
		fmt.Errorf("%v", errors.New("invalid token"))
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Errorf("%v", errors.New("invalid claims"))
		return nil, errors.New("invalid claims")
	}

	if !claims.VerifyAudience(audience, true) {
		fmt.Errorf("%v", errors.Errorf("invalid audience for sub %s:  have %s, want %s", claims["sub"], audience, claims["aud"]))
		return nil, errors.Errorf("invalid audience for sub %s:  have %s, want %s", claims["sub"], audience, claims["aud"])
	}

	if !claims.VerifyIssuer(issuer, true) {
		fmt.Errorf("%v", errors.Errorf("invalid issuer for sub %s:  have %s, want %s", claims["sub"], issuer, claims["iss"]))
		return nil, errors.Errorf("invalid issuer for sub %s:  have %s, want %s", claims["sub"], issuer, claims["iss"])
	}
	return claims, nil
}

func main() {
	r := mux.NewRouter()
	loginHandler := http.HandlerFunc(LoginHandler)
	requestHandler := http.HandlerFunc(RequestHandler)
	r.Handle("/login", ValidateJWTMiddleWare(loginHandler))
	r.Handle("/request", ValidateJWTMiddleWare(requestHandler))
	http.Handle("/", r)
	

	// TODO: add something like server listening on...
	http.ListenAndServe(":8080", nil)
}
