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

package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"reflect"
)

const (
	hashSize = 512
)

func GetMaxTextSizeByBits(bits int) (uint, error) {
	var maxTextSize int

	maxTextSize = (bits / 8) - (2 * hashSize / 8) - (2)

	if maxTextSize <= 0 {
		return 0, errors.New("Size key is too small for used hash algorithm")
	}

	return (uint(maxTextSize)), nil
}

func GetMaxTextSizeByKey(keyIn interface{}) (uint, error) {
	var keyReflectValue reflect.Value
	var key *rsa.PrivateKey
	var pubKey *rsa.PublicKey
	var castOk bool
	var maxTextSize int

	keyReflectValue = reflect.ValueOf(keyIn)

	if keyReflectValue.Kind() != reflect.Ptr {
		return 0, errors.New("Input variable was not pointer")
	}

	switch keyReflectValue.Elem().Type().String() {
	case "rsa.PrivateKey":
		{
			key, castOk = keyIn.(*rsa.PrivateKey)
			if castOk != true {
				return 0, errors.New("Failed to assertion inputed key as RSA private key")
			}

			maxTextSize = (key.N.BitLen() / 8) - (2 * hashSize / 8) - (2)
		}
	case "rsa.PublicKey":
		{
			pubKey, castOk = keyIn.(*rsa.PublicKey)
			if castOk != true {
				return 0, errors.New("Failed to assertion inputed key as RSA public key")
			}

			maxTextSize = (pubKey.N.BitLen() / 8) - (2 * hashSize / 8) - (2)
		}
	default:
		{
			return 0, errors.New("Input variable was not RSA private or public key")
		}
	}

	if maxTextSize < 1 {
		return 0, errors.New("Size of inputed RSA key is too small for used hash algorithm")
	}

	return (uint(maxTextSize)), nil
}

func GenKey(bits int) (*rsa.PrivateKey, error) {
	var err error
	var key *rsa.PrivateKey

	_, err = GetMaxTextSizeByBits(bits)
	if err != nil {
		return nil, err
	}

	key, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func Sign(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	var err error
	var hash [sha512.Size]byte
	var sing []byte

	hash = sha512.Sum512(data[:])

	sing, err = rsa.SignPSS(rand.Reader, key, crypto.SHA512, hash[:], nil)
	if err != nil {
		return nil, err
	}

	return sing[:], nil
}

func Verify(data []byte, pubKey *rsa.PublicKey, sign []byte) error {
	var err error
	var hash [sha512.Size]byte

	hash = sha512.Sum512(data[:])

	err = rsa.VerifyPSS(pubKey, crypto.SHA512, hash[:], sign[:], nil)
	if err != nil {
		return err
	}

	return nil
}

func Encrypt(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	var err error
	var encryptedData []byte

	encryptedData, err = rsa.EncryptOAEP(sha512.New(), rand.Reader, pubKey, data[:], nil)
	if err != nil {
		return nil, err
	}

	return encryptedData[:], nil
}

func Decrypt(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	var err error
	var decryptedData []byte

	decryptedData, err = rsa.DecryptOAEP(sha512.New(), rand.Reader, key, data[:], nil)
	if err != nil {
		return nil, err
	}

	return decryptedData[:], nil
}

func RandBytes(quantity uint) ([]byte, error) {
	var err error
	var randBytes []byte

	if quantity == 0 {
		return nil, errors.New("Requested quantity of random bytes was zero")
	}

	randBytes = make([]byte, quantity)

	_, err = rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(randBytes, make([]byte, quantity)) == 1 {
		return nil, errors.New("All generated bytes are zero")
	}

	return randBytes[:], nil
}
