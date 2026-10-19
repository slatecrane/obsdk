// Command gendirectory rewrites banks/atruvia/directory.json from Atruvia's
// published list of XS2A endpoints (Xs2aApiDirectory.json), which Atruvia
// updates after mergers and migrations:
//
//	go run ./banks/atruvia/gendirectory              # download the current list
//	go run ./banks/atruvia/gendirectory -in FILE     # or read a downloaded copy
//
// Review the diff: removed bank codes are usually mergers.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const source = "https://atruvia.de/uploads/files/Xs2aApiDirectory.json"

type entry struct {
	Code string `json:"code"`
	BIC  string `json:"bic"`
	Name string `json:"name"`
	URL  string `json:"url"` // API root, without /v1
}

func main() {
	in := flag.String("in", "", "read this file instead of downloading "+source)
	out := flag.String("out", "banks/atruvia/directory.json", "output file")
	flag.Parse()

	raw, err := read(*in)
	if err != nil {
		log.Fatal(err)
	}
	var src []struct {
		Bank    string `json:"Bank"`
		Country string `json:"Country"`
		BIC     string `json:"BIC"`
		Code    string `json:"Bank Code"`
		URL     string `json:"URL XS2A API"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &src); err != nil {
		log.Fatalf("read directory: %v", err)
	}
	seen := map[string]bool{}
	var list []entry
	for _, s := range src {
		u := strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(s.URL), "/"), "/v1")
		code := strings.ReplaceAll(s.Code, " ", "")
		switch {
		case len(code) != 8 || !strings.HasPrefix(u, "https://"):
			log.Printf("skipping %q: code %q, url %q", s.Bank, s.Code, s.URL)
			continue
		case seen[code]:
			// Volksbank Mittelhessen also lists its MEINE BANK brand under the
			// same code; the first entry wins, the other is reachable via base_url.
			log.Printf("skipping %q: bank code %s is listed twice", s.Bank, code)
			continue
		}
		seen[code] = true
		list = append(list, entry{Code: code, BIC: strings.TrimSpace(s.BIC), Name: strings.TrimSpace(s.Bank), URL: u})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Code < list[j].Code })
	b, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %d banks\n", *out, len(list))
}

func read(file string) ([]byte, error) {
	if file != "" {
		return os.ReadFile(file)
	}
	c := &http.Client{Timeout: time.Minute}
	res, err := c.Get(source)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", source, res.StatusCode)
	}
	return io.ReadAll(res.Body)
}
