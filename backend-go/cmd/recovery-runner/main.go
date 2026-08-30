package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/recoveryrunner"
)

func main() {
	service, err := recoveryrunner.New(os.Getenv("RECOVERY_RUNNER_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("RECOVERY_RUNNER_LISTEN_ADDRESS")
	if address == "" {
		address = "127.0.0.1:8092"
	}
	server := &http.Server{Addr: address, Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("safe local recovery runner listening on %s", address)
	log.Fatal(server.ListenAndServe())
}
