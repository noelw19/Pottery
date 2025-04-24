package lib

import (
	"log"
	"os"
)

func GenerateCertsFlag(flag *bool) {
	if *flag {

		log.Println("")
		log.Println("-- Flag detected --")
		log.Println("")
		log.Println("generateCerts will now generate certificates if not present")
		log.Println("")
		// check if ca cert exist
		log.Println("Checking for certs directory")
		log.Println("")

		if FileExist("./certs") {
			// directory exists
			log.Printf("./certs directory found\n")
			// check for certs
			log.Println("Checking for ca, server and client directories within ./certs")

			// check if ca directory exist
			if !FileExist("./certs/ca") {
				log.Println("ca directory doesn't exist, creating dir and generating certs")
				CreateDir("./certs/ca")
				CreateDir("./certs/server")
				CreateDir("./certs/client")
				GenAll()
				// gen certs
			} else {

				// check if server directory exist
				if !FileExist("./certs/server") {
					log.Println("server directory doesn't exist, creating dir and generating certs")
					CreateDir("./certs/server")
					// gen certs
					GenServer()
				} else {
					log.Println("server directory does exist")
					// check certs
					if !FileExist("./certs/server/server.crt") || !FileExist("./certs/server/server.key") {
						GenServer()
					} else {
						log.Println(YellowLog("server.crt and server.key already exist - delete these files to regenerate them using current CA"))
					}
				}

				// check if client directory exist
				if !FileExist("./certs/client") {
					log.Println("client directory doesn't exist, creating dir and generating certs")
					CreateDir("./certs/client")
					// gen certs
					GenClient()
				} else {
					log.Println("client directory does exist")
					// check certs
					if !FileExist("./certs/client/client.crt") || !FileExist("./certs/client/client.key") {
						GenClient()
					} else {
						log.Println(YellowLog("client.crt and client.key already exist - delete these files to regenerate them using current CA"))
					}
				}
			}

		} else {
			// dir doesnt exist
			// create all certificates
			log.Println("./certs directory not found")
			log.Println("Creating certs directory")

			CreateDir("./certs")
			CreateDir("./certs/server")
			CreateDir("./certs/ca")
			CreateDir("./certs/client")

			GenAll()
		}

		log.Println("")
		log.Println(GreenLog("Job Complete exiting Pottery"))
		log.Println(GreenLog("Restart to begin using new certificates for MTLS"))
		log.Println("")
		os.Exit(0)
	}
}
