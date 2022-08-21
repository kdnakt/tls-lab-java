package main

import (
	"log"
	"net/http"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	http.HandleFunc("/", HelloServer)
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
