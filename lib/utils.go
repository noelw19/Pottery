package lib

import (
	"encoding/json"
	"errors"
	"log"
	"os"
)

func FileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// file does not exist
		return false
	} else {
		// cert dir exists
		return true
	}
}

func CreateDir(path string) error {
	return os.Mkdir(path, 0777)
}

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"

func GreenLog(s string) string {
	return Green + s + Reset
}

func RedLog(s string) string {
	return Red + s + Reset
}

func YellowLog(s string) string {
	return Yellow + s + Reset
}

func AddToJSON(b []byte, key string, value string) ([]byte, error) {
	var jsonData map[string]interface{}

	err := json.Unmarshal(b, &jsonData)
	if err != nil {
		log.Println("Error adding property to JSON byte array: ", err)
		return nil, err
	}

	jsonData[key] = value

	return json.Marshal(jsonData)
}