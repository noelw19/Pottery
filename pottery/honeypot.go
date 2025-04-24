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

type Honeypot struct {
	DeviceIP string
	Port     uint16
	Name     string
	State    string
	Logger   *log.Logger
	Wordlist []string
}

type IServers interface {
	*Honeypot
	Run()
}

type middleware struct {
	mux     http.Handler
	potName string
	config  *Config
}

type ctxKey string

type ctxKeys struct {
	geolocation ctxKey
}

var contextKeys ctxKeys = ctxKeys{
	geolocation: ctxKey("geolocation"),
}

func (m middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ctx := context.WithValue(req.Context(), "user", "unknown")
	// ctx = context.WithValue(ctx, "__requestStartTimer__", time.Now())
	// req = req.WithContext(ctx)

	// if loopback address then empty string will get current server ip
	ip := strings.Split(req.RemoteAddr, ":")[0]
	if ip == "127.0.0.1" || strings.Contains(ip, "192.168.") {
		ip = ""
	}
	emoji := '\U0001F92E'
	// emoji2 := '\U0001F9DC'

	log.Println(fmt.Sprintf("%c Endpoint Hit - %s - %s %c", emoji, req.RequestURI, ip, emoji))
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

	// ctx = context.WithValue(req.Context(), contextKeys.geolocation, geo)
	// newReq := req.WithContext(ctx)

	// if has a parent and is not a parent itself
	if m.config.HasParent() && !m.config.IsParent() {
		geo.ParentPass(m.config.Parent)
		ep.ParentPass(m.config.Parent)
	}

	m.mux.ServeHTTP(rw, req)

	// start := req.Context().Value("__requestStartTimer__").(time.Time)
	// log.Println("request duration: ", time.Since(start))
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
	for _, word := range pot.Wordlist {
		helloMux.HandleFunc(handlerFactory(word))
	}

	helloMux.HandleFunc("/popper", handlePopper)

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", pot.DeviceIP, pot.Port),
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
		Handler:      middleware{helloMux, pot.Name, conf},
	}
}
