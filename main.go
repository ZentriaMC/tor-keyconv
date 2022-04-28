package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	tored25519 "github.com/cretz/bine/torutil/ed25519"
)

var keyFile string

func main() {
	flag.StringVar(&keyFile, "key", "", "Path to Onion service secret key. You're looking for 'hs_ed25519_secret_key'")
	flag.Parse()

	if keyFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		panic(fmt.Errorf("failed to read %s: %w", keyFile, err))
	}

	secretKey := tored25519.PrivateKey(data[32:])
	fmt.Printf("ED25519-V3:%s\n", base64.StdEncoding.EncodeToString(secretKey))
}
