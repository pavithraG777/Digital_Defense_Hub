package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/commandsandbox"
)

func main() {
	service, err := commandsandbox.New(os.Getenv("COMMAND_SANDBOX_ARTIFACT_ROOT"), os.Getenv("COMMAND_SANDBOX_TOKEN"), os.Getenv("COMMAND_SANDBOX_DOCKER_EXECUTABLE"), 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("COMMAND_SANDBOX_LISTEN_ADDRESS")
	if address == "" {
		address = "127.0.0.1:8091"
	}
	server := &http.Server{Addr: address, Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("isolated command sandbox listening on %s", address)
	log.Fatal(server.ListenAndServe())
}
