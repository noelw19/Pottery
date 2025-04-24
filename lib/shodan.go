package lib

import (
	"fmt"
	"io"
	"net/http"
)

func Shodan_Search(ip string) error {
	apiKey := ENV(ENV_VAR.SHODAN)
	path := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	r, err := http.Get(path)
	if err != nil {
		// deal with err
		return err
	}

	defer r.Body.Close()

	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Println("Error reading body:", err)
		}
		if n == 0 {
			break
		}
		fmt.Print(string(buf[:n]))
	}

	return nil
}