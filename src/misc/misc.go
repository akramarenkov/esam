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

package misc

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
)

import (
	"github.com/urfave/cli/v2"
)

import (
	"esam/src/opts2"
	"esam/src/passwd"
)

func ExtractAddr(fullAddr string) string {
	var elements []string
	var elementsLen int

	elements = strings.Split(fullAddr, ":")
	elementsLen = len(elements[:])

	if elementsLen > 1 {
		return strings.Join(elements[:elementsLen-1], "")
	}

	return fullAddr
}

func SubCommandBashCompleter(c *cli.Context) {
	for _, flag := range c.Command.VisibleFlags() {
		for _, name := range flag.Names() {
			switch name {
			case "h", "help":
			default:
				{
					if len(name) > 1 {
						fmt.Printf("--%v\n", name)
					} else {
						fmt.Printf("-%v\n", name)
					}
				}
			}
		}
	}
}

func PasswordValidator(password interface{}) error {
	var passwordAsString string
	var castOk bool

	passwordAsString, castOk = password.(string)
	if !castOk {
		return errors.New("Failed to cast password to string")
	}

	return passwd.CheckDifficulty(passwordAsString, &opts2.PasswdDifficulty)
}

func LeaveAvailableGroups(groups []string) ([]string, error) {
	var err error
	var availableGroups []string

	availableGroups = make([]string, 0)

	for index := range groups {
		_, err = user.LookupGroup(groups[index])
		if err == nil {
			availableGroups = append(availableGroups, groups[index])
		}
	}

	return availableGroups[:], nil
}
