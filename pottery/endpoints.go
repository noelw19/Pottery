package pottery

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/noelw19/honeypot/lib"
	"github.com/noelw19/honeypot/logging"
)

func handlePopper(w http.ResponseWriter, req *http.Request) {
	record := logging.GenerateRecord(req)
	if err := logging.LogRecord(record); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Turns out your popper\n")
}

func mainDynamicHandler(w http.ResponseWriter, req *http.Request) {
	record := logging.GenerateRecord(req)
	if err := logging.LogRecord(record); err != nil {
		log.Fatal(err)
	}

	// dynamic returns
	fmt.Fprintf(w, "Welcome to pottery\n")
}

// function will return the arguements needed for mux HandleFunc
// iterate a wordlist and create a endpoint string, plus a handler for this endpoint
func handlerFactory(url_path string) (string, http.HandlerFunc) {
	// log.Println("New Endpoint: ", url_path)

	return "/" + url_path, func(w http.ResponseWriter, r *http.Request) {
		mainDynamicHandler(w, r)
	}
}

func fuzzDetect(w http.ResponseWriter, r *http.Request, pot *Honeypot, conf *Config) {
	// add more to the interesting hits list
	interestingHits := []string{
		"db.ini",
		".git",
		"robots.txt",
		".sql",
	}

	for _, v := range interestingHits {
		if strings.Contains(r.URL.String(), v) {
			fuzzingLog := fmt.Sprintf("Fuzzing detected on port: %d, pot: %s", pot.Port, pot.Name)

			alert := &fuzzAlert{
				AttackerIp:  r.RemoteAddr,
				PotName:     pot.Name,
				Endpoint:    r.URL.String(),
				Description: fuzzingLog,
			}

			// added fuzz log desc for better logging on the parent side
			jsonBytes, err := json.Marshal(alert)
			if err != nil {
				fmt.Println("Error marshaling fuzz alert into json bytes.")
			} else {
				if conf.HasParent() {
					log.Println(lib.RedLog(fuzzingLog))
					lib.MTLS_Fuzzing_Alert(conf.Parent, jsonBytes, conf.HasParent())
				} else {
					gunEmoji := "\U0001F52B"
					log.Println(lib.RedLog("FUZZING ALERT --- \n"), gunEmoji, string(jsonBytes), gunEmoji)
				}
			}
			w.WriteHeader(200)
			w.Write([]byte("Nothing here."))
			return
		}
	}

	fmt.Fprintf(w, "Endpoint not found")
}
