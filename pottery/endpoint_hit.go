package pottery

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/noelw19/honeypot/db"
	"github.com/noelw19/honeypot/lib"
)

type Endpoint_hit struct {
	Ip         string `json:"ip"`
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	Headers    string `json:"headers"`
	User_agent string `json:"user_agent"`
	Honeypot   string `json:"honeypot"`
	Req_body   string `json:"req_body"`
}

func (ep *Endpoint_hit) ParentPass(parentIP string) error {
	json, err := json.Marshal(ep)
	if err != nil {
		log.Println("There was an error marshalling endpoint hit data to pass to parent")
		return err
	}
	lib.SendToParent(parentIP, lib.MTLS_MESSAGE_TYPE_ENDPOINT_HIT, json)
	return nil
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

func (ep *Endpoint_hit) Populate(r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	ep.Ip = ip
	ep.Endpoint = r.URL.String()
	ep.Method = r.Method
	ep.User_agent = r.UserAgent()

	headers := ""
	// iterate headers and create string for db
	for k, v := range r.Header {
		current := k + ":"
		for i, v1 := range v {
			current += v1
			if i != len(v)-1 {
				current += ","
			}
		}
		current += "; "
		headers += current
	}
	ep.Headers = headers
	bod := r.Body
	if bod != nil {
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println("error reading req body: ", err)
			return
		}
		ep.Req_body = string(body)
	}

}
