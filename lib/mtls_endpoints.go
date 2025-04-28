package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func ipdataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		log.Println("Body is empty")
		fmt.Fprintf(w, "Need data in req body\n")

		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error parsing response body when receiving in parent: ", err)
		fmt.Fprintf(w, "Error reading bytes in req body.\n")
		return
	} else {
		geo := &GeoData{}
		wholeBodyMapped := map[string]any{}

		// body includes name of honeypot for logging purposes
		// then unmarshal and save to DB
		err := json.Unmarshal(body, &wholeBodyMapped)
		if err != nil {
			log.Println("error unmarshaling data in ip data parent receiver: ", err)
		} else {
			potName := wholeBodyMapped["name"]

			geo.Unmarshal(body)
			logging := fmt.Sprintf("Received ip data from child: %s", potName)
			log.Println(GreenLog(logging))
			geo.SaveToDB()
		}
	}

	r.Body.Close()
	fmt.Fprintf(w, "Success\n")
}

func endpointhitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		log.Println("Body is empty")
		fmt.Fprintf(w, "Need data in req body\n")

		return
	}
	body, err1 := io.ReadAll(r.Body)
	if err1 != nil {
		log.Println("Error parsing response body when sending to parent: ", err1)
		fmt.Fprintf(w, "Error reading bytes from req body\n")

	} else {
		ep := &Endpoint_hit{}
		ep.Unmarshal(body)

		log.Println(GreenLog("Received endpoint hit data from child: " + ep.Honeypot))
		ep.SaveToDB()
	}

	r.Body.Close()
	fmt.Fprintf(w, "Success\n")
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		log.Println("Body is empty")
		fmt.Fprintf(w, "Need data in req body\n")

		return
	}
	body, err1 := io.ReadAll(r.Body)
	if err1 != nil {
		log.Println("Error parsing response body when sending to parent: ", err1)
		fmt.Fprintf(w, "Error reading bytes from req body\n")

	} else {
		type verifyData struct {
			Honeypot string
		}
		vd := &verifyData{}
		json.Unmarshal(body, vd)
		log.Println(GreenLog("MTLS Verified from child instance with the naming scheme: " + vd.Honeypot))
	}

	r.Body.Close()
	fmt.Fprintf(w, "Success\n")
}

func fuzzingAlertHandler(w http.ResponseWriter, r *http.Request) {
	// fmt.Println("received fuzzing alert")
	if r.Body == nil {
		log.Println("Body is empty")
		fmt.Fprintf(w, "Need data in req body\n")

		return
	}
	body, err1 := io.ReadAll(r.Body)
	if err1 != nil {
		log.Println("Error parsing response body when sending to parent: ", err1)
		fmt.Fprintf(w, "Error reading bytes from req body\n")
	}

	gunEmoji  := "\U0001F52B"

	log.Println(RedLog("FUZZING ALERT --- \n"), gunEmoji, string(body), gunEmoji)
}
