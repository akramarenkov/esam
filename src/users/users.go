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

package users

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

const (
	passwdFilePath      = "/etc/passwd"
	userItemsDelimiter  = '\n'
	userFieldsDelimiter = ":"
)

/*
https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_431
https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_278
*/

var (
	validUserNameCharacters = []rune{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
		'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '_', '-',
	}
)

func ListNames() ([]string, error) {
	var err error
	var list []string
	var file *os.File
	var bufFile *bufio.Reader
	var userItem string
	var userFields []string

	list = make([]string, 0)

	file, err = os.Open(passwdFilePath)
	if err != nil {
		return nil, err
	}

	bufFile = bufio.NewReader(file)

	for {
		userItem, err = bufFile.ReadString(userItemsDelimiter)
		if err != nil && err != io.EOF {
			return nil, err
		}

		if err == io.EOF {
			break
		}

		userFields = strings.Split(userItem, userFieldsDelimiter)
		if len(userFields) > 0 {
			if userFields[0] != "" {
				list = append(list, userFields[0])
			}
		}
	}

	return list, nil
}

func ValidateName(name string) error {
	var nameAsRunes []rune

	nameAsRunes = []rune(name)

	if len(nameAsRunes) < 1 {
		return errors.New("User name can't be empty")
	}

	if len(nameAsRunes) > 32 {
		return errors.New("User name can't be longer than 32 characters")
	}

	for _, char := range nameAsRunes {
		var charIsValid bool

		for _, validChar := range validUserNameCharacters {
			if char == validChar {
				charIsValid = true
				break
			}
		}

		if !charIsValid {
			return errors.New("User name contain characters not from the allowed character set: [a-z][A-Z][0-9][._-]")
		}
	}

	if nameAsRunes[0] == rune('-') {
		return errors.New("User name cannot begin with a hyphen-minus character")
	}

	return nil
}
