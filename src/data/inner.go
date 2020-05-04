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

package data

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"reflect"
	"strconv"
)

import (
	"github.com/akramarenkov/esam/src/crypt"
	"github.com/akramarenkov/esam/src/keysconv"
)

/*
IMPORTANT!

Field with ESAMPubKey name can't be in self signed map!
But it may equal SignSubject field
*/

/*
Use constants:
  - ESAMPubKeyFieldName
  - SignSubjectFieldName
  - signFieldSuffix
*/

func signStruct(structData interface{}, structSign interface{}, key *rsa.PrivateKey, selfSignedFields map[string]bool) error {
	var (
		err error

		signerESAMPubKey ESAMPubKey

		structDataRValue      reflect.Value
		structSignRValue      reflect.Value
		structDataFieldRValue reflect.Value
		structSignFieldRValue reflect.Value
		structDataField       reflect.StructField
		structSignField       reflect.StructField
		esamPubKeyFieldFound  bool
		fieldsMatchingFound   bool
	)

	if structData == nil {
		return errors.New("Pointer to struct with data can't be nil")
	}

	if structSign == nil {
		return errors.New("Pointer to struct with sign can't be nil")
	}

	if key == nil {
		return errors.New("Key pointer can't be nil")
	}

	signerESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&key.PublicKey)
	if err != nil {
		return err
	}

	structDataRValue = reflect.ValueOf(structData)
	structSignRValue = reflect.ValueOf(structSign)

	if structDataRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable of struct with data is not pointer")
	}

	if structSignRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable of struct with sign is not pointer")
	}

	structDataRValue = structDataRValue.Elem()
	structSignRValue = structSignRValue.Elem()

	if structDataRValue.Kind() != reflect.Struct {
		return errors.New("Input variable with data is not Struct")
	}

	if structSignRValue.Kind() != reflect.Struct {
		return errors.New("Input variable with sign is not Struct")
	}

	/* Not in 'self signing' mode 'sign subject' field must be filled with the public key in PEM corresponding to the provided private key */
	if len(selfSignedFields) == 0 {
		if !structSignRValue.FieldByName(SignSubjectFieldName).IsValid() {
			return errors.New("Sign subject field is not valid")
		}

		if !structSignRValue.FieldByName(SignSubjectFieldName).CanSet() {
			return errors.New("Sign subject field can't be changed")
		}

		structSignRValue.FieldByName(SignSubjectFieldName).Set(reflect.ValueOf(signerESAMPubKey))
	}

	if len(selfSignedFields) > 0 {
		if selfSignedFields[ESAMPubKeyFieldName] == true {
			return errors.New(ESAMPubKeyFieldName + " can't be in self signed map")
		}
	}

	for i := 0; i < structDataRValue.NumField(); i++ {
		structDataFieldRValue := structDataRValue.Field(i)
		structDataField := structDataRValue.Type().Field(i)

		if structDataField.Name == ESAMPubKeyFieldName {
			esamPubKeyFieldData, castOk := structDataFieldRValue.Interface().(ESAMPubKey)
			if !castOk {
				return errors.New("Failed to assertion " + ESAMPubKeyFieldName + " field")
			}

			/* In 'self signing' mode key in ESAMPubKey field must match the public key corresponding to the provided private key */
			if len(selfSignedFields) > 0 {
				if signerESAMPubKey.Equal(&esamPubKeyFieldData) == false {
					return errors.New("Signer key and key in the structure do not match")
				}
			}

			esamPubKeyFieldFound = true
			break
		}
	}

	if esamPubKeyFieldFound == false {
		return errors.New(ESAMPubKeyFieldName + " field was not found")
	}

	for i := 0; i < structDataRValue.NumField(); i++ {
		structDataFieldRValue = structDataRValue.Field(i)
		structDataField = structDataRValue.Type().Field(i)

		fieldsMatchingFound = false
		for j := 0; j < structSignRValue.NumField(); j++ {
			structSignFieldRValue = structSignRValue.Field(j)
			structSignField = structSignRValue.Type().Field(j)

			if structSignField.Name == (structDataField.Name + signFieldSuffix) {
				if structSignFieldRValue.Kind() == reflect.Slice {
					if structSignFieldRValue.CanSet() {
						fieldsMatchingFound = true
						break
					}
				}
			}
		}

		if !fieldsMatchingFound {
			return errors.New("Not matching found between data field and sign field")
		}

		/* In 'self signing' mode skip field if for her set to false flag in selfSignedFields map */
		if len(selfSignedFields) > 0 {
			if !selfSignedFields[structDataField.Name] {
				continue
			}
		}

		var fieldData []byte

		fieldData = nil
		if structDataField.Name == ESAMPubKeyFieldName {
			esamPubKeyFieldData, castOk := structDataFieldRValue.Interface().(ESAMPubKey)
			if !castOk {
				return errors.New("Failed to assertion " + ESAMPubKeyFieldName + " field")
			}

			fieldData = esamPubKeyFieldData
		} else {
			switch structDataFieldRValue.Kind() {
			case reflect.String:
				fieldData = []byte(structDataFieldRValue.String())

			case reflect.Bool:
				fieldData = []byte(strconv.FormatBool(structDataFieldRValue.Bool()))

			default:
				return errors.New("Unsupported field type")
			}
		}

		if fieldData != nil {
			fieldSign, err := crypt.Sign(fieldData, key)
			if err != nil {
				return err
			}

			fieldSignBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(fieldSign)))
			base64.StdEncoding.Encode(fieldSignBase64, fieldSign)

			structSignFieldRValue.Set(reflect.ValueOf(fieldSignBase64))
		} else {
			return errors.New("Could not determine field data")
		}
	}

	return nil
}

func verifyStruct(structData interface{}, structSign interface{}, selfSignedFields map[string]bool) error {
	var (
		err error

		structDataRValue      reflect.Value
		structSignRValue      reflect.Value
		structDataFieldRValue reflect.Value
		structSignFieldRValue reflect.Value
		structDataField       reflect.StructField
		structSignField       reflect.StructField
		fieldsMatchingFound   bool

		esamPubKeyInRSA        *rsa.PublicKey
		signSubjectPubKeyInRSA *rsa.PublicKey
	)

	if structData == nil {
		return errors.New("Pointer to struct with data can't be nil")
	}

	if structSign == nil {
		return errors.New("Pointer to struct with sign can't be nil")
	}

	if len(selfSignedFields) > 0 {
		if selfSignedFields[ESAMPubKeyFieldName] == true {
			return errors.New(ESAMPubKeyFieldName + " can't be in self signed map")
		}
	}

	structDataRValue = reflect.ValueOf(structData)
	structSignRValue = reflect.ValueOf(structSign)

	if structDataRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable of struct with data is not pointer")
	}

	if structSignRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable of struct with sign is not pointer")
	}

	structDataRValue = structDataRValue.Elem()
	structSignRValue = structSignRValue.Elem()

	if structDataRValue.Kind() != reflect.Struct {
		return errors.New("Input variable with data is not Struct")
	}

	if structSignRValue.Kind() != reflect.Struct {
		return errors.New("Input variable with sign is not Struct")
	}

	for i := 0; i < structDataRValue.NumField(); i++ {
		structDataFieldRValue := structDataRValue.Field(i)
		structDataField := structDataRValue.Type().Field(i)

		if structDataField.Name == ESAMPubKeyFieldName {
			esamPubKeyFieldData, castOk := structDataFieldRValue.Interface().(ESAMPubKey)
			if !castOk {
				return errors.New("Failed to assertion " + ESAMPubKeyFieldName + " field")
			}

			esamPubKeyInRSA, err = keysconv.PubKeyInPEMToRSA(esamPubKeyFieldData)
			if err != nil {
				return err
			}

			break
		}
	}

	for j := 0; j < structSignRValue.NumField(); j++ {
		structSignFieldRValue := structSignRValue.Field(j)
		structSignField := structSignRValue.Type().Field(j)

		if structSignField.Name == SignSubjectFieldName {
			signSubjectFieldData, castOk := structSignFieldRValue.Interface().(ESAMPubKey)
			if !castOk {
				return errors.New("Failed to assertion sign subject field")
			}

			signSubjectPubKeyInRSA, err = keysconv.PubKeyInPEMToRSA(signSubjectFieldData)
			if err != nil {
				return err
			}

			break
		}
	}

	if esamPubKeyInRSA == nil {
		return errors.New(ESAMPubKeyFieldName + " field was not found")
	}

	if signSubjectPubKeyInRSA == nil {
		return errors.New("Sign subject field was not found")
	}

	for i := 0; i < structDataRValue.NumField(); i++ {
		structDataFieldRValue = structDataRValue.Field(i)
		structDataField = structDataRValue.Type().Field(i)

		fieldsMatchingFound = false
		for j := 0; j < structSignRValue.NumField(); j++ {
			structSignFieldRValue = structSignRValue.Field(j)
			structSignField = structSignRValue.Type().Field(j)

			if structSignField.Name == (structDataField.Name + signFieldSuffix) {
				if structSignFieldRValue.Kind() == reflect.Slice {
					if structSignFieldRValue.CanSet() {
						fieldsMatchingFound = true
						break
					}
				}
			}
		}

		if !fieldsMatchingFound {
			return errors.New("Not matching found between data field and sign field")
		}

		var fieldData []byte

		fieldData = nil
		if structDataField.Name == ESAMPubKeyFieldName {
			esamPubKeyFieldData, castOk := structDataFieldRValue.Interface().(ESAMPubKey)
			if !castOk {
				return errors.New("Failed to assertion " + ESAMPubKeyFieldName + " field")
			}

			fieldData = esamPubKeyFieldData
		} else {
			switch structDataFieldRValue.Kind() {
			case reflect.String:
				fieldData = []byte(structDataFieldRValue.String())

			case reflect.Bool:
				fieldData = []byte(strconv.FormatBool(structDataFieldRValue.Bool()))

			default:
				return errors.New("Unsupported field type")
			}
		}

		if fieldData != nil {
			var verifyAsWellAsSelfSigned bool

			verifyAsWellAsSelfSigned = false

			if len(selfSignedFields) > 0 {
				if selfSignedFields[structDataField.Name] {
					/* Can be signed with both a sign subject field key and self signed (i.e. signed ESAMPubKey) */
					verifyAsWellAsSelfSigned = true
				}
			}

			if structDataField.Name == ESAMPubKeyFieldName && verifyAsWellAsSelfSigned == true {
				return errors.New(ESAMPubKeyFieldName + " can't be in self signed map")
			}

			fieldSignBase64, castOk := structSignFieldRValue.Interface().([]byte)
			if !castOk {
				return errors.New("Failed to assertion sign field")
			}

			fieldSign := make([]byte, base64.StdEncoding.DecodedLen(len(fieldSignBase64)))

			fieldSignLen, err := base64.StdEncoding.Decode(fieldSign, fieldSignBase64)
			if err != nil {
				return err
			}

			err = crypt.Verify(fieldData, signSubjectPubKeyInRSA, fieldSign[:fieldSignLen])
			if err != nil {
				if verifyAsWellAsSelfSigned == false {
					return err
				} else {
					err = crypt.Verify(fieldData, esamPubKeyInRSA, fieldSign[:fieldSignLen])
					if err != nil {
						return err
					}
				}
			}
		} else {
			return errors.New("Could not determine field data")
		}
	}

	return nil
}

func zeroTwoStructsFields(one interface{}, two interface{}, fields map[string]bool) error {
	var (
		err            error
		oneRValue      reflect.Value
		twoRValue      reflect.Value
		oneFieldRValue reflect.Value
		oneField       reflect.StructField
	)

	if one == nil {
		return errors.New("Struct pointer can't be nil")
	}

	if two == nil {
		return errors.New("Struct pointer can't be nil")
	}

	oneRValue = reflect.ValueOf(one)
	twoRValue = reflect.ValueOf(two)

	if oneRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable is not a pointer")
	}

	if twoRValue.Kind() != reflect.Ptr {
		return errors.New("Input variable is not a pointer")
	}

	oneRValue = oneRValue.Elem()
	twoRValue = twoRValue.Elem()

	if oneRValue.Kind() != reflect.Struct {
		return errors.New("Input variable is not a Struct")
	}

	if twoRValue.Kind() != reflect.Struct {
		return errors.New("Input variable is not a Struct")
	}

	if len(fields) > 0 {
		for i := 0; i < oneRValue.NumField(); i++ {
			oneFieldRValue = oneRValue.Field(i)
			oneField = oneRValue.Type().Field(i)

			if !oneRValue.FieldByName(oneField.Name).IsValid() {
				return errors.New("Field is not valid")
			}

			if !twoRValue.FieldByName(oneField.Name).IsValid() {
				return errors.New("Field is not valid")
			}

			if oneFieldRValue.Kind() == reflect.Struct {
				if !oneRValue.FieldByName(oneField.Name).CanAddr() {
					return errors.New("Field cannot have address")
				}

				if !twoRValue.FieldByName(oneField.Name).CanAddr() {
					return errors.New("Field cannot have address")
				}

				err = zeroTwoStructsFields(oneRValue.FieldByName(oneField.Name).Addr().Interface(), twoRValue.FieldByName(oneField.Name).Addr().Interface(), fields)
				if err != nil {
					return err
				}
			}

			if fields[oneField.Name] {
				if !oneRValue.FieldByName(oneField.Name).CanSet() {
					return errors.New("Field can't be changed")
				}

				if !twoRValue.FieldByName(oneField.Name).CanSet() {
					return errors.New("Field can't be changed")
				}

				oneRValue.FieldByName(oneField.Name).Set(reflect.Zero(oneRValue.FieldByName(oneField.Name).Type()))
				twoRValue.FieldByName(oneField.Name).Set(reflect.Zero(twoRValue.FieldByName(oneField.Name).Type()))
			}
		}
	}

	return nil
}
