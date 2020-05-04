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

package passwd

import (
	"errors"
	"strings"
)

var (
	typicalSequences = []string{
		"~!@#$%^&*()_+|",
		"1234567890-=\\",
		"qwertyuiop[]",
		"asdfghjkl;'",
		"zxcvbnm,./",
		"1qaz",
		"2wsx",
		"3edc",
		"4rfv",
		"5tgb",
		"6yhn",
		"7ujm",
		"8ik,",
		"9ol.",
		"0p;/",
		"zse4",
		"xdr5",
		"cft6",
		"vgy7",
		"bhu8",
		"nji9",
		"mko0",
		",lp-",
		".;[=",
		"/']\\",
	}
)

/* Speed doesn't care us */
func revertRunes(runes []rune) []rune {
	var (
		out      []rune
		runesLen int
	)

	runesLen = len(runes)

	out = make([]rune, runesLen)

	for index := range runes {
		out[runesLen-index-1] = runes[index]
	}

	return out
}

func findSequences(password []rune, sequencesMinLength int) error {
	var (
		passwordLen      int
		subString        string
		subStringReverse string
	)

	passwordLen = len(password)

	for i := range password {
		if (i + sequencesMinLength) > passwordLen {
			return nil
		}

		subString = strings.ToLower(string(password[i : i+sequencesMinLength]))
		subStringReverse = strings.ToLower(string(revertRunes(password[i : i+sequencesMinLength])))

		for j := range typicalSequences {
			if strings.Contains(typicalSequences[j], subString) || strings.Contains(typicalSequences[j], subStringReverse) {
				return errors.New("Sequence finded")
			}
		}
	}

	return nil
}
