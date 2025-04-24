package lib

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type T_ENV_VAR struct {
	SHODAN string
}

var ENV_VAR = T_ENV_VAR{
	SHODAN: "SHODAN_API_KEY",
}

func ENV(key string) string {
  // load .env file
  err := godotenv.Load(".env")
  if err != nil {
    log.Fatalf("Error loading .env file")
  }

  return os.Getenv(key)
}
