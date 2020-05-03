/*
  ESAM - Elementary SSH accounts management
  Copyright (C) 2020 Aleksandr Kramarenko akramarenkov@yandex.ru

  This file is part of ESAM.

  ESAM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  ESAM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ESAM.  If not, see <https://www.gnu.org/licenses/>.
*/

package keysconv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

import (
	"github.com/akramarenkov/esam/src/crypt"
)

func PEMIsEncrypted(data []byte) (bool, error) {
	var pemBlock *pem.Block

	pemBlock, _ = pem.Decode(data)
	if pemBlock == nil {
		return false, errors.New("Failed to decode PEM block")
	}

	if x509.IsEncryptedPEMBlock(pemBlock) {
		return true, nil
	}

	return false, nil
}

func KeyInPEMToRSA(pemKey []byte, password string) (*rsa.PrivateKey, error) {
	var err error
	var keyPemBlock *pem.Block
	var key *rsa.PrivateKey
	var resultPemBytes []byte

	keyPemBlock, _ = pem.Decode(pemKey)
	if keyPemBlock == nil || keyPemBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("Failed to decode PEM block as private key")
	}

	resultPemBytes = keyPemBlock.Bytes

	if x509.IsEncryptedPEMBlock(keyPemBlock) {
		resultPemBytes, err = x509.DecryptPEMBlock(keyPemBlock, []byte(password))
		if err != nil {
			return nil, err
		}
	}

	keyAsInterface, err := x509.ParsePKCS8PrivateKey(resultPemBytes)
	if err != nil {
		return nil, err
	}

	key, ok := keyAsInterface.(*rsa.PrivateKey)
	if ok != true {
		return nil, errors.New("Failed to assertion private key")
	}

	return key, nil
}

func KeyInRSAToPEM(key *rsa.PrivateKey, password string) ([]byte, error) {
	var err error
	var keyInPKCS8 []byte
	var keyBuffer *bytes.Buffer
	var keyInBytes []byte

	keyInPKCS8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyPemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyInPKCS8,
	}

	if password != "" {
		keyPemBlock, err = x509.EncryptPEMBlock(rand.Reader, keyPemBlock.Type, keyPemBlock.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}

	keyBuffer = bytes.NewBuffer(nil)

	err = pem.Encode(keyBuffer, keyPemBlock)
	if err != nil {
		return nil, err
	}

	keyInBytes = keyBuffer.Bytes()

	return keyInBytes, nil
}

func PubKeyInPEMToRSA(pemPubKey []byte) (*rsa.PublicKey, error) {
	var err error
	var pubKeyPemBlock *pem.Block
	var pubKey *rsa.PublicKey

	pubKeyPemBlock, _ = pem.Decode(pemPubKey)
	if pubKeyPemBlock == nil || pubKeyPemBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("Failed to decode PEM block as public key")
	}

	pubKeyAsInterface, err := x509.ParsePKIXPublicKey(pubKeyPemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubKeyAsInterface.(*rsa.PublicKey)
	if ok != true {
		return nil, errors.New("Failed to assertion public key")
	}

	return pubKey, nil
}

func PubKeyInRSAToPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	var err error
	var pubKeyInPKIX []byte
	var pubKeyBuffer *bytes.Buffer
	var pubKeyInBytes []byte

	pubKeyInPKIX, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	pubKeyPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyInPKIX,
	}

	pubKeyBuffer = bytes.NewBuffer(nil)

	err = pem.Encode(pubKeyBuffer, pubKeyPemBlock)
	if err != nil {
		return nil, err
	}

	pubKeyInBytes = pubKeyBuffer.Bytes()

	return pubKeyInBytes, nil
}

func GenAndSaveKeyPair(keyPath string, pubKeyPath string, bits int, password string) error {
	var err error
	var keyFile, pubKeyFile *os.File
	var keyPair *rsa.PrivateKey
	var keyInPem []byte
	var pubKeyInPem []byte

	keyFile, err = os.OpenFile(keyPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	pubKeyFile, err = os.OpenFile(pubKeyPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer pubKeyFile.Close()

	keyPair, err = crypt.GenKey(bits)
	if err != nil {
		return err
	}

	keyInPem, err = KeyInRSAToPEM(keyPair, password)
	if err != nil {
		return err
	}

	pubKeyInPem, err = PubKeyInRSAToPEM(&keyPair.PublicKey)
	if err != nil {
		return err
	}

	_, err = keyFile.Write(keyInPem)
	if err != nil {
		return err
	}

	_, err = pubKeyFile.Write(pubKeyInPem)
	if err != nil {
		return err
	}

	return nil
}

func KeyIsEncrypted(keyPath string) (bool, error) {
	var err error
	var keyFile *os.File
	var keyFileContent []byte
	var keyIsEncrypted bool

	keyFile, err = os.Open(keyPath)
	if err != nil {
		return false, err
	}
	defer keyFile.Close()

	keyFileContent, err = ioutil.ReadAll(keyFile)
	if err != nil {
		return false, err
	}

	keyIsEncrypted, err = PEMIsEncrypted(keyFileContent)
	if err != nil {
		return false, err
	}

	return keyIsEncrypted, nil
}

func LoadKeyFromFile(keyPath string, password string) (*rsa.PrivateKey, error) {
	var err error
	var keyFile *os.File
	var keyFileContent []byte
	var key *rsa.PrivateKey

	keyFile, err = os.Open(keyPath)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	keyFileContent, err = ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}

	key, err = KeyInPEMToRSA(keyFileContent, password)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func LoadPubKeyFromFile(pubKeyPath string) (*rsa.PublicKey, error) {
	var err error
	var pubKeyFile *os.File
	var pubKeyFileContent []byte
	var pubKey *rsa.PublicKey

	pubKeyFile, err = os.Open(pubKeyPath)
	if err != nil {
		return nil, err
	}
	defer pubKeyFile.Close()

	pubKeyFileContent, err = ioutil.ReadAll(pubKeyFile)
	if err != nil {
		return nil, err
	}

	pubKey, err = PubKeyInPEMToRSA(pubKeyFileContent)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}
