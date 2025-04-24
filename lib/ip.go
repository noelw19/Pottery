package lib

import (
	"log"
	"net"
	"strings"
)

func GetServerIP() string {
	ifaces, err := net.Interfaces()
	// handle err
	if err != nil {
		log.Println("Error getting interfaces to determine current IP address")
	}
	var ip net.IP
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		// handle err
		if err != nil {
			log.Println("Error getting current address of network interface")

		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if strings.HasPrefix(v.IP.String(), "192.") || strings.HasPrefix(v.IP.String(), "10.") {
					ip = v.IP
				}
			case *net.IPAddr:
				if strings.HasPrefix(v.IP.String(), "192.") || strings.HasPrefix(v.IP.String(), "10.") {
					ip = v.IP
				}
			}
			// process IP address
		}

	}
	return ip.String()
}
