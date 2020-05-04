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

package ui

import (
	"errors"
	"fmt"
	"os"
	"reflect"
)

import (
	"github.com/akramarenkov/esam/src/data"
)

import (
	"github.com/AlecAivazis/survey/v2"
	"gopkg.in/yaml.v3"
)

const (
	selectSkipItem = "Skip"
)

func PrintError(message string, err error, args ...interface{}) (int, error) {
	var (
		details string
	)

	details = fmt.Sprintf(". Details: %v\n", err)

	if len(args) > 0 {
		return fmt.Fprintf(os.Stderr, message+details, args...)
	} else {
		return fmt.Fprintf(os.Stderr, message+details)
	}
}

func PrintInfo(message string, args ...interface{}) (int, error) {
	if len(args) > 0 {
		return fmt.Printf(message+"\n", args...)
	} else {
		return fmt.Printf(message + "\n")
	}
}

func Select(message string, list interface{}, selectedItem interface{}, pageSize int) error {
	var (
		err    error
		castOk bool

		listRValue             reflect.Value
		selectedItemRValue     reflect.Value
		selectedItemElemRValue reflect.Value
		stringMetodIsPresent   bool
		listAsStrings          []string

		questions []*survey.Question
		answer    string
	)

	if list == nil {
		return errors.New("List of items can't be nil")
	}

	if selectedItem == nil {
		return errors.New("Selected item can't be nil")
	}

	if pageSize < 1 {
		return errors.New("Page size can't be less 1")
	}

	listRValue = reflect.ValueOf(list)
	selectedItemRValue = reflect.ValueOf(selectedItem)

	if selectedItemRValue.Kind() != reflect.Ptr {
		return errors.New("Selected item variable type is not a pointer")
	}

	selectedItemElemRValue = selectedItemRValue.Elem()

	switch listRValue.Kind() {
	case reflect.Array:
	case reflect.Slice:

	default:
		return errors.New("List of items is not a Array or Slice")
	}

	if selectedItemElemRValue.Type() != listRValue.Type().Elem() {
		return errors.New("Type of selected item not equal type of items list")
	}

	if listRValue.Len() == 0 {
		return errors.New("Empty items list")
	}

	_, stringMetodIsPresent = selectedItemElemRValue.Type().MethodByName("String")
	if !stringMetodIsPresent {
		return errors.New("Selected item does not support method String()")
	}

	_, stringMetodIsPresent = selectedItemRValue.Type().MethodByName("FromString")
	if !stringMetodIsPresent {
		return errors.New("Selected item does not support method FromString()")
	}

	listAsStrings = make([]string, 0)
	listAsStrings = append(listAsStrings, selectSkipItem)

	for index := 0; index < listRValue.Len(); index++ {
		listItemRValue := listRValue.Index(index)
		listItemStringMethodRValue := listItemRValue.MethodByName("String").Call([]reflect.Value{})

		if len(listItemStringMethodRValue) != 1 {
			return errors.New("Method String() return unexpected number of values")
		}

		if !listItemStringMethodRValue[0].IsValid() {
			return errors.New("Value returned from String() method is invalid")
		}

		if !listItemStringMethodRValue[0].CanInterface() {
			return errors.New("Value returned from String() method does not have interface")
		}

		listItemAsString, castOk := listItemStringMethodRValue[0].Interface().(string)
		if !castOk {
			return errors.New("Failed to cast value returned from String() method to string")
		}

		listAsStrings = append(listAsStrings, listItemAsString)
	}

	questions = []*survey.Question{
		{
			Name: "Select from list",
			Prompt: &survey.Select{
				Message: message,
				Options: listAsStrings,
			},
			Validate: survey.Required,
		},
	}

	err = survey.Ask(questions, &answer, survey.WithPageSize(pageSize))
	if err != nil {
		return err
	}

	if answer == selectSkipItem {
		return nil
	}

	selectedItemFromStringMethodRValue := selectedItemRValue.MethodByName("FromString").Call([]reflect.Value{reflect.ValueOf(answer)})

	if len(selectedItemFromStringMethodRValue) != 1 {
		return errors.New("Method FromString() return unexpected number of values")
	}

	if !selectedItemFromStringMethodRValue[0].IsValid() {
		return errors.New("Value returned from FromString() method is invalid")
	}

	if !selectedItemFromStringMethodRValue[0].CanInterface() {
		return errors.New("Value returned from FromString() method does not have interface")
	}

	if selectedItemFromStringMethodRValue[0].Interface() != nil {
		err, castOk = selectedItemFromStringMethodRValue[0].Interface().(error)
		if !castOk {
			return errors.New("Failed to cast value returned from FromString() method to error")
		}

		return err
	}

	return nil
}

func Edit(message string, editableData interface{}) error {
	var (
		err error

		editableDataRValue   reflect.Value
		editableDataAsBytes  []byte
		editableDataAsString string

		prompt *survey.Editor
	)

	if editableData == nil {
		return errors.New("Editable data can't be nil")
	}

	editableDataRValue = reflect.ValueOf(editableData)

	if editableDataRValue.Kind() != reflect.Ptr {
		return errors.New("Editable data variable type is not a pointer")
	}

	editableDataAsBytes, err = yaml.Marshal(editableData)
	if err != nil {
		return err
	}

	editableDataAsString = string(editableDataAsBytes)

	prompt = &survey.Editor{
		Message:       message,
		FileName:      "*.yaml",
		Default:       editableDataAsString,
		AppendDefault: true,
		HideDefault:   true,
	}

	Validator := func(valueIn interface{}) error {
		var (
			editableDataTmpRValue reflect.Value
			editableDataTmp       interface{}
			valueInAsString       string
			tester                data.Tester
			castOk                bool
		)

		editableDataTmpRValue = reflect.New(editableDataRValue.Elem().Type())

		if !editableDataTmpRValue.IsValid() {
			return errors.New("Zero copy of editable data value is invalid")
		}

		if !editableDataTmpRValue.CanInterface() {
			return errors.New("Zero copy of editable data value does not have interface")
		}

		editableDataTmp = editableDataTmpRValue.Interface()

		valueInAsString, castOk = valueIn.(string)
		if !castOk {
			return errors.New("Failed to cast editable data to string")
		}

		err = yaml.Unmarshal([]byte(valueInAsString), editableDataTmp)
		if err != nil {
			return err
		}

		tester, castOk = editableDataTmp.(data.Tester)
		if castOk {
			err = tester.Test(data.ToleratesEmptyFieldsNo)
			if err != nil {
				return err
			}
		}

		return nil
	}

	err = survey.AskOne(prompt, &editableDataAsString, survey.WithValidator(Validator))
	if err != nil {
		return err
	}

	err = yaml.Unmarshal([]byte(editableDataAsString), editableData)
	if err != nil {
		return err
	}

	return nil
}

func ReadPassword(message string, validator func(interface{}) error) (string, error) {
	var (
		err      error
		prompt   *survey.Password
		password string
	)

	prompt = &survey.Password{
		Message: message,
	}

	if validator == nil {
		err = survey.AskOne(prompt, &password)
	} else {
		err = survey.AskOne(prompt, &password, survey.WithValidator(validator))
	}
	if err != nil {
		return "", err
	}

	return password, nil
}

func AskYesNo(message string) (bool, error) {
	var (
		err    error
		prompt *survey.Confirm
		answer bool
	)

	prompt = &survey.Confirm{
		Message: message,
	}

	err = survey.AskOne(prompt, &answer)
	if err != nil {
		return false, err
	}

	return answer, nil
}
