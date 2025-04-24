package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/noelw19/honeypot/lib"
	"github.com/noelw19/honeypot/logging"
	"github.com/noelw19/honeypot/pottery"
)

func checkInternetAccess() bool {
	_, err := http.Get("https://www.google.com")
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func flagProccessor() {
	generateCertsFlag := flag.Bool("generateCerts", false, "generate ca, server and client certificates")
	flag.Parse()

	// generate certs if not present
	lib.GenerateCertsFlag(generateCertsFlag)
}

func main() {

	log.Printf("")
	log.Println("--- Starting Pottery ---")
	log.Println("")

	flagProccessor()

	logging.Start()
	log.Println("Checking internet connection")

	hasInternet := checkInternetAccess()
	if !hasInternet {
		log.Println("No internet access...")
		log.Fatal("Check internet access and restart Pottery")
	}

	log.Println("Creating Honeypots")
	log.Println("")

	// what else do i need to store
	// have
	// - IP, Geolocation
	// - Req Data, body

	hp := &pottery.Honeypots{}
	hp.Start()
}
