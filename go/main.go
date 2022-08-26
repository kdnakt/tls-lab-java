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
	log.Println("start HelloServer")
	http.HandleFunc("/", HelloServer)
	if err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
