package lib

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"strings"
)

type wordlist struct {
	words [][]byte
}

func wordlist_generate() *wordlist {
	wl := &wordlist{}
	wl.readWordlists()
	return wl
}

func (w *wordlist) randomGen(used []int, max int) int {
	random := rand.Intn(max)
	// if used re-roll
	if slices.Contains(used, random) {

		return w.randomGen(used, max)
	}
	wordToReturn := string(w.words[random])
	// if int re-roll
	if _, err := strconv.ParseInt(wordToReturn, 10, 64); err == nil {
		return w.randomGen(used, max)
	}

	return random
}

func (w *wordlist) GetWordlistEntry_Random(used []int) (string, int) {
	randomInt := w.randomGen(used, len(w.words))
	wordToReturn := strings.ReplaceAll(string(w.words[randomInt]), "\r\n", "")
	wordToReturn = strings.ReplaceAll(wordToReturn, "\n", "")
	return wordToReturn, randomInt
}

func Generate_worldlist_array(max int) []string {
	wl := wordlist_generate()
	used_wordlist_indexes := []int{}
	words := []string{}

	// having issues here why is it returning more
	// than max words ?
	for range max {
		word, random := wl.GetWordlistEntry_Random(used_wordlist_indexes)
		used_wordlist_indexes = append(used_wordlist_indexes, random)
		words = append(words, word)
	}
	return words
}

func (w *wordlist) readWordlists() {
	wordlistPath := "./wordlists"
	files, err := os.ReadDir(wordlistPath)
	if err != nil {
		log.Panicln("Error reading wordlist dir")
	}
	var words [][]byte

	for i, filename := range files {

		file, err := os.ReadFile("./wordlists/" + filename.Name())
		if err != nil {
			log.Panicln("Error reading wordlist ")
			if i == len(files)-1 {
				w.words = words
				return
			}
			continue
		}

		// possible bugs here reading file lines into mem
		fileReader := bytes.NewReader(file)
		scanner := bufio.NewScanner(fileReader)
		for scanner.Scan() {
			words = append(words, []byte(scanner.Text()))
		}
	}
	w.words = words
}

var wl = `pipeline
preise
projekt
publico
quickbuy
rabota
racing
radmin
rainbow
rando
rb_logs
rb_tools
realtor
recovery
revista
routines
runway
samara
seite
sendcard
seo-blog
seopanel
servis
setting
sflib
shablon
shares
shop1
shortcut
similar
smiley
solar
sondages
speller
sugarcrm
supplies
sxema
tenpay
testi
tiles
tp-files
trivia
ueberuns
ultimate
untitled
fukuoka
varios
visits
visual
signIn
GetPage
webcasts
webchat
webevent
weblink
webring
where
winkel
wissen
xtree2b`

func InitWordList() {
	f, err := os.Create("./wordlists/initialWordlist.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	l, err := f.WriteString(wl)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	fmt.Println(l, "bytes written successfully")
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}
