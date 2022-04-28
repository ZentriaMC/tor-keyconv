package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	tored25519 "github.com/cretz/bine/torutil/ed25519"
)

var (
	hsKeyPrefix = []byte(`== ed25519v1-secret: type0 ==`)
)

var keyFile string

func main() {
	if err := entrypoint(); err != nil {
		panic(err)
	}
}

func entrypoint() (err error) {
	flag.StringVar(&keyFile, "key", "", "Path to Onion service secret key. You're looking for 'hs_ed25519_secret_key'")
	flag.Parse()

	if keyFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("failed to read %s: %w", keyFile, err)
		return
	}

	// 32 byte header + 64 byte key
	if l := len(data); l != 96 {
		err = fmt.Errorf("invalid key - expected len %d, was %d", 96, l)
		return
	}

	if !bytes.Equal(data[0:len(hsKeyPrefix)], hsKeyPrefix) {
		err = fmt.Errorf("invalid key - invalid header")
		return
	}

	secretKeyRaw := data[32:] // Start from 32nd
	secretKey := tored25519.PrivateKey(secretKeyRaw)
	encoded := base64.StdEncoding.EncodeToString(secretKey)
	fmt.Printf("ED25519-V3:%s\n", encoded)
	return
}
