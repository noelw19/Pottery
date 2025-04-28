package pottery

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/noelw19/honeypot/db"
	"github.com/noelw19/honeypot/lib"
)

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

func (data *GeoData) GetGeolocation(ip string) error {
	resp, err := http.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		return err
	}
	//We Read the response body on the line below.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return err
	}

	return nil
}

func (data *GeoData) ParentPass(parentIP string, name string) error {
	json, err := data.Marshal()
	if err != nil {
		log.Println("There was an error marshalling geolocation")
		return err
	}
	appendedJSON, err := lib.AddToJSON(json, "name", name)
	if err != nil {
		log.Println("There was an error marshalling geolocation")
		return err
	}
	lib.SendToParent(parentIP, lib.MTLS_MESSAGE_TYPE_IP_DATA, appendedJSON)
	return nil
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

func (data *GeoData) Marshal() ([]byte, error) {
	json, err := json.Marshal(data)
	if err != nil {
		return []byte{}, err
	}
	return json, nil
}
