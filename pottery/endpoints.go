package pottery

import (
	"fmt"
	"log"
	"net/http"
	// "math/rand"

	"github.com/noelw19/honeypot/logging"
)

func handleIndex(w http.ResponseWriter, req *http.Request) {
	record := logging.GenerateRecord(req)
	if err := logging.LogRecord(record); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(w, "Welcome\n")
}

func handlePopper(w http.ResponseWriter, req *http.Request) {
	record := logging.GenerateRecord(req)
	if err := logging.LogRecord(record); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Turns out your popper\n")
}

// func dynamicReturns() string {
// 	arr := []string{
// 	}
// 	randomInt := rand.Intn(len(arr))
// 	return arr[randomInt]
// }

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

    return "/"+url_path, func(w http.ResponseWriter, r *http.Request) {
        mainDynamicHandler(w, r)
    }
}