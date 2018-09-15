package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"path"
)

var (
	stateDir = flag.String("state_dir", "", "where to store keys and server state")
)

const (
	caKeyName = "ca_key"
)

func persistKey(key *ecdsa.PrivateKey, dir, keyName string) error {
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("could not marshal private key: %v", err)
	}
	f, err := os.Create(path.Join(dir, keyName))
	if err != nil {
		return fmt.Errorf("could not open %q for writing: %v", path.Join(dir, keyName), err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}); err != nil {
		return fmt.Errorf("could not write private key: %v", err)
	}

	pubAsSSHKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("could not convert public key to ssh.PublicKey: %v", err)
	}
	pubF, err := os.Create(path.Join(dir, keyName+".pub"))
	if err != nil {
		return fmt.Errorf("could not open %q for writing: %v", path.Join(dir, keyName+".pub"), err)
	}
	defer pubF.Close()
	if _, err := pubF.Write(ssh.MarshalAuthorizedKey(pubAsSSHKey)); err != nil {
		return fmt.Errorf("could not write public key: %v", err)
	}

	return nil
}

func readFileAsBytes(filepath string) ([]byte, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return []byte{}, fmt.Errorf("could not open %q for reading: %v", filepath, err)
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(f); err != nil {
		return []byte{}, fmt.Errorf("failed reading from %q: %v", filepath, err)
	}
	return buf.Bytes(), nil
}

func loadKey(dir, keyName string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := readFileAsBytes(path.Join(dir, keyName))
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing private key: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast parsed key to *ecdsa.PrivateKey; is a %T", key)
	}

	pubAsSSHKey, err := ssh.NewPublicKey(&ecKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not convert public key to ssh.PublicKey: %v", err)
	}
	marshaled := ssh.MarshalAuthorizedKey(pubAsSSHKey)

	pubBytes, err := readFileAsBytes(path.Join(dir, keyName+".pub"))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(marshaled, pubBytes) {
		return nil, errors.New("private key does not match public key")
	}

	return ecKey, nil
}

func main() {
	flag.Parse()

	if *stateDir == "" {
		log.Fatal("--state_dir must be set")
	} else if stat, err := os.Stat(*stateDir); os.IsNotExist(err) || !stat.IsDir()  {
		log.Fatal("--state_dir %q does not exist or is not a directory.")
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate CA key: %v", err)
	}
	if err := persistKey(caKey, *stateDir, caKeyName); err != nil {
		log.Fatalf("Could not persist CA Key: %v", err)
	}

	if _, err := loadKey(*stateDir, caKeyName); err != nil {
		log.Fatalf("Failed to verify persisted key: %v", err)
	}
}
