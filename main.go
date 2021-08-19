package main

import (
	"github.com/gorilla/mux"
	"net/http"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// print out username and password
    w.WriteHeader(http.StatusOK)
	w.Write([]byte("Congrats user login\n"))
}

func RequestHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}

func main() {
    r := mux.NewRouter()
    r.HandleFunc("/login", LoginHandler)
    r.HandleFunc("/request", RequestHandler)
	http.Handle("/", r)

	// add something like server listening on...
	http.ListenAndServe(":8080", nil)
}