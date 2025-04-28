package pottery

import (
	// "context"

	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/noelw19/honeypot/lib"
)

type fuzzAlert struct {
	AttackerIp  string
	PotName     string
	Endpoint    string
	Description string
}

type Honeypot struct {
	DeviceIP string
	Port     uint16
	Name     string
	State    string
	Logger   *log.Logger
	Wordlist []string
}

type middleware struct {
	mux     http.Handler
	potName string
	config  *Config
}

func (m middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	// if loopback address then empty string will get current server ip
	ip := strings.Split(req.RemoteAddr, ":")[0]
	if ip == "127.0.0.1" || strings.Contains(ip, "192.168.") {
		ip = ""
	}
	emoji := '\U0001F92E'
	// emoji2 := '\U0001F9DC'

	log.Printf("%c Endpoint Hit - %s - %s %c\n", emoji, req.RequestURI, ip, emoji)
	geo := &GeoData{}
	err := geo.GetGeolocation(ip)
	if err != nil {
		fmt.Println("Couldnt get geolocation data: ", err)
	}

	err = geo.SaveToDB()
	if err != nil {
		fmt.Println("error saving to db: ", err)
	}

	ep := &Endpoint_hit{}
	ep.Honeypot = m.potName
	ep.Populate(req)
	ep.SaveToDB()

	// if has a parent and is not a parent itself
	if m.config.HasParent() && !m.config.IsParent() {
		geo.ParentPass(m.config.Parent, ep.Honeypot)
		ep.ParentPass(m.config.Parent)
	}

	m.mux.ServeHTTP(rw, req)
}

func potNameLog(pot *Honeypot) {
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w, pot.Port, "|", pot.Name)
	w.Flush()
}

func (pot *Honeypot) Run(endpoint_count int, conf *Config) *http.Server {
	// generate wordlist slice to create handler factory
	endpointCount := 10
	wordlistSlice := lib.Generate_worldlist_array(endpointCount)
	pot.Wordlist = wordlistSlice

	potNameLog(pot)

	helloMux := http.NewServeMux()
	// take the random word array and iterate.
	// pass to handler factory to create handler
	// with word as endpoint
	ipRateLimiter := lib.NewIPRateLimiter()

	// added rate limiter but it is invoked on each handle func,
	// will probably needto add these to all endpioints not including parent MTLS
	for _, word := range pot.Wordlist {
		endpoint, handler := handlerFactory(word)
		helloMux.HandleFunc(endpoint, lib.RateLimitMiddleware(ipRateLimiter, handler))
	}

	helloMux.HandleFunc("/popper", lib.RateLimitMiddleware(ipRateLimiter, handlePopper))
	helloMux.HandleFunc("/", lib.RateLimitMiddleware(ipRateLimiter, func(w http.ResponseWriter, r *http.Request) {
		fuzzDetect(w,r, pot, conf)
	}))

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", pot.DeviceIP, pot.Port),
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Handler:      middleware{helloMux, pot.Name, conf},
	}
}
