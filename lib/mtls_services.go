package lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/noelw19/honeypot/db"
)

func LoadTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("./certs/server/server.crt", "./certs/server/server.key")
	if err != nil {
		log.Fatalf("Failed to load server key pair: %v", err)
	}

	caCert, err := os.ReadFile("./certs/ca/ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
}

func CreateMTLSServer(port string, tlsConfig *tls.Config) *http.Server {
	serv := &http.Server{}

	go func() {
		router := http.NewServeMux()
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("in MTLS")
			fmt.Fprintf(w, "IN MTLS\n")
		})

		// implement handlers to save data that comes in to the database
		// TODO unmarshal data into struct and use same functionality to save to local db
		router.HandleFunc("POST /ipdata", ipdataHandler)
		router.HandleFunc("POST /endpointhit", endpointhitHandler)
		router.HandleFunc("POST /verify", verifyHandler)
		router.HandleFunc("POST /fuzzingalert", fuzzingAlertHandler)

		// create MTLS Server or client
		server := &http.Server{
			Addr:      ":" + port,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		log.Println("")
		log.Println(GreenLog(fmt.Sprintf("MTLS Parent server listening on %s...", port)))
		serv = server
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	return serv
}

var MTLS_MESSAGE_TYPE_IP_DATA string = "ipdata"
var MTLS_MESSAGE_TYPE_ENDPOINT_HIT string = "endpointhit"

func SendToParent(parentIP string, dataType string, data []byte) {
	log.Println("Sending to " + dataType + " to parent")
	client := MTLS_Client()

	// Make a request
	parentURL := fmt.Sprintf("https://%s/%s", parentIP, dataType)
	requestBody := bytes.NewReader(data)
	r, err := client.Post(parentURL, "application/json", requestBody)
	if err != nil {
		log.Println("Error sending data to parent: ", err)
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded) {
			log.Println(RedLog("Connection refused by parent, check that the parent is running."), err)
			log.Println(RedLog("Alternatively change the parent config to \"none\" to run as a standalone honeypot"))
			log.Fatalln(RedLog("Exiting Pottery"))
		}
		return
	}

	if r.Body == nil {
		log.Println("Body is empty")
		return
	}
	body, err1 := io.ReadAll(r.Body)
	if err1 != nil {
		log.Println("Error parsing response body when sending to parent: ", err1)
	} else {
		log.Println(string(body))

	}

	r.Body.Close()
}

func MTLS_Client() *http.Client {
	caCert, _ := os.ReadFile("./certs/ca/ca.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, _ := tls.LoadX509KeyPair("./certs/client/client.crt", "./certs/client/client.key")

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
		Timeout: 5 * time.Second,
	}
}

func MTLS_Fuzzing_Alert(parentIP string, data []byte, hasParent bool) {
	if !hasParent {
		return
	}

	log.Println("Passing fuzzing alert to parent.")
	client := MTLS_Client()
	URL_path := fmt.Sprintf("https://%s/fuzzingalert", parentIP)
	// passing - IP of attacker, endpoint being hit, pot name,
	reader := bytes.NewReader(data)

	// will only post data to parent no checking if data was received etc
	_, err := client.Post(URL_path, "application/json", reader)
	if err != nil {
		fmt.Println(RedLog("could not make post to parent for fuzzing alert"))
	}

}

// calls the verify endpoint to validate that the certificates provided work
func MTLS_Verify_Certs(parentIP string, potName string) {
	log.Println("Verifying MTLS Connectivity")
	client := MTLS_Client()

	type verifyData struct {
		Honeypot string
	}

	// Make a request
	vd := verifyData{
		Honeypot: potName,
	}
	jsonBytes, err := json.Marshal(vd)
	if err != nil {
		log.Println("There was an issue marshalling honeypot name for MTLS verify request")
		log.Fatalln(RedLog("Exiting Pottery"))
	}

	jsonReader := bytes.NewReader(jsonBytes)
	parentURL := fmt.Sprintf("https://%s/verify", parentIP)
	r, err := client.Post(parentURL, "application/json", jsonReader)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			log.Println(RedLog("Connection refused by parent, check that the parent is running: "), err)
			log.Fatalln(RedLog("Exiting Pottery"))
		} else if errors.Is(err, context.DeadlineExceeded) {
			log.Println(RedLog("Request to verify MTLS connection timed out, check that the parent is running: "), err)
			log.Fatalln(RedLog("Exiting Pottery"))
		} else {
			log.Println("Error sending data to parent: ", err)

		}
		return
	}

	if r.Body == nil {
		log.Println("Body is empty")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error parsing response body verifying MTLS connectivity: ", err)
	} else {
		if strings.Contains(string(body), "Success") {
			log.Println(GreenLog("MTLS Connectivity with parent verified!"))
			return
		}
	}
	r.Body.Close()
	log.Fatalln(RedLog("There is an issue with the ca.crt, client.crt or client.key provided, MTLS connectivity failed."))
}

// copied geolocation code because of import cycle issue

type GeoData struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Region      string  `json:"regionName"`
	ISP         string  `json:"isp"`
	Lat         float64 `json:"lat"`
	Long        float64 `json:"lon"`
	IP          string  `json:"query"`
}

func (data *GeoData) SaveToDB() error {
	ll := db.Db{
		Filename: "./honeypot.db",
	}
	// check if ip already exists in table
	res := ll.Get_IP_From_DB(data.IP)
	if len(*res) > 0 {
		err := ll.Update_IP_Hit(data.IP)
		if err != nil {
			log.Println("error updating IP hit: ", data.IP, err)
		}
		return nil
	}

	err := ll.Set_IP_DATA(data.IP, data.Country, data.CountryCode, data.City, data.Region, data.ISP)
	if err != nil {
		log.Println("Error saving data to db: ", err)
	}

	return nil
}

func (data *GeoData) Unmarshal(body []byte) error {
	err := json.Unmarshal(body, &data)
	if err != nil {
		return err
	}
	return nil
}

type Endpoint_hit struct {
	Ip         string `json:"ip"`
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	Headers    string `json:"headers"`
	User_agent string `json:"user_agent"`
	Honeypot   string `json:"honeypot"`
	Req_body   string `json:"req_body"`
}

func (ep *Endpoint_hit) SaveToDB() {
	ll := db.Db{
		Filename: "./honeypot.db",
	}
	err := ll.Set_Endpoint_Hit(ep.Ip, ep.Endpoint, ep.Method, ep.Headers, ep.User_agent, ep.Honeypot, ep.Req_body)
	if err != nil {
		fmt.Println("Error saving endpoint hit to DB: ", err)
	}

	res := ll.Get_Endpoint_Hit_All()
	if res != nil {

	}
}

func (data *Endpoint_hit) Unmarshal(body []byte) error {
	err := json.Unmarshal(body, &data)
	if err != nil {
		return err
	}
	return nil
}
