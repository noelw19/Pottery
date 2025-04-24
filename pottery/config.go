package pottery

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/noelw19/honeypot/lib"
)

type Config struct {
	CurrentIP     string
	Ports         []uint16 `json:"ports"`
	NamingScheme  string   `json:"namingScheme"`
	Parent        string   `json:"parent"`
	EndpointCount int      `json:"endpoint_count"`
}

// validate and set config defaults if some are not set
func (hp *Honeypots) validateConfig() {
	// if no endpoint count in config, defaults sets to 0
	// set this to a default of 10
	if hp.Config.EndpointCount == 0 {
		hp.Config.EndpointCount = 10
	}
	// set default port to 8080 if none supplied
	if len(hp.Config.Ports) == 0 {
		hp.Config.Ports = []uint16{8080}
	}

	if hp.Config.NamingScheme == "" {
		hp.Config.NamingScheme = "Valhalla"
	}

	// parent probably needs port
	if hp.Config.Parent == "" {
		hp.Config.Parent = "none"
	}

	if !strings.Contains(hp.Config.Parent, ":") {
		log.Println("Configuration item for parent doesn't have port number")
		log.Fatal("e.g: 192.168.6.13:8443")
	}
}

func (c *Config) IsParent() bool {
	return c.Parent == "127.0.0.1:8443"
}

func (c *Config) MTLS_Begin()  {
	if c.IsParent() || c.HasParent() {
		fmt.Println("MTLS Start")
		
	}
}

func (c *Config) HasParent() bool {
	if c.Parent == "none" || c.Parent == "127.0.0.1:8443"{
		return false
	}
	return true
}

func (c *Config) GetParent() string {
	return c.Parent
}

func (hp *Honeypots) GenerateConfig() {
	log.Println("Generating Config from file")
	var config *Config
	createConfigFileIfNotExist()
	conf, err := os.ReadFile("./config.json")
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(conf, &config)
	if err != nil {
		log.Fatal("Cannot unmarshal config file: ", err)
	}

	deviceIP := lib.GetServerIP()
	log.Println("Current IP: ", deviceIP)
	config.CurrentIP = deviceIP
	hp.Config = config

	hp.validateConfig()
	marshalAndSaveConfig(string(conf), *hp.Config)
}

func createConfigFileIfNotExist() {
	if _, err := os.Stat("./config.json"); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		err := os.WriteFile("./config.json", []byte("{}"), 0755)
		if err != nil {
			fmt.Println("unable to write file: ", err)
		}
	}
}

func removeCurrentIPFromConfigJSON(jsonBytes []byte) []byte {
	lines := strings.Split(string(jsonBytes), "\t")
	freshArr := []string{}
	for _, i := range lines {
		if !strings.Contains(i, "CurrentIP") {
			freshArr = append(freshArr, i)
		}
	}

	return []byte(strings.Join(freshArr, "\t"))
}

func marshalAndSaveConfig(confRead string, cfg Config) {
	// if config read is not empty then return
	// otherwise clean new config in memory and save to file
	if string(confRead) != "{}" {
		return
	}

	log.Println("No config file present")
	log.Println("Saving Default config to file")

	jsonBytes, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		log.Println("Error saving fresh defaults to config")
	}

	cleanedBytes := removeCurrentIPFromConfigJSON(jsonBytes)

	err = os.WriteFile("./config.json", cleanedBytes, 0755)
	if err != nil {
		fmt.Println("unable to write file: ", err)
	}
}
