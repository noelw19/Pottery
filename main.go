package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/noelw19/honeypot/lib"
	"github.com/noelw19/honeypot/logging"
	"github.com/noelw19/honeypot/pottery"
)

func checkInternetAccess() bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Get("https://www.google.com")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Println(lib.RedLog("Request timed out while verifying internet connectivity, check your internet connection and restart Pottery."))
		} else {
			if !strings.Contains(err.Error(), "no such host") {
				log.Println(err)
			}
		}
		return false
	}
	return true
}

func flagProccessor() {
	generateCertsFlag := flag.Bool("generateCerts", false, "generate ca, server and client certificates")
	clearCertsFlag := flag.Bool("clearCerts", false, "delete all MTLS certificates")
	flag.Parse()

	// generate certs if not present
	lib.ClearCertsFlag(clearCertsFlag)
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
		fmt.Println("")
		log.Println(lib.RedLog("No internet access..."))
		log.Fatal(lib.RedLog("Exiting Pottery\n"))
	}

	log.Println("Creating Honeypots")
	log.Println("")

	hp := &pottery.Honeypots{}
	hp.Start()
}
