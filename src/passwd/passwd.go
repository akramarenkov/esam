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
	"unicode"
)

import (
	crypt "github.com/nathanaelle/password/v2"
	"golang.org/x/crypto/bcrypt"
)

import (
	"github.com/akramarenkov/esam/src/opts"
)

type DifficultyOpt struct {
	MinLength          int
	DiffCase           bool
	Numbers            bool
	Specials           bool
	MaxIdentSymPercent int
	ForbidSequences    int
}

type difficultyStat struct {
	Length          int
	LowerCase       int
	UpperCase       int
	Numbers         int
	Specials        int
	EffectiveLength int
}

const (
	PasswdHashAlgoBCrypt = "bcrypt"
	PasswdHashAlgoSHA512 = "sha512"
)

func bcryptCalcHash(password string) (string, error) {
	var (
		err  error
		hash []byte
	)

	hash, err = bcrypt.GenerateFromPassword([]byte(password), opts.BCryptPasswdHashCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func bcryptCompareHash(password string, hash string) bool {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
		return true
	}

	return false
}

func sha512CalcHash(password string) (string, error) {
	return crypt.SHA512.SetOptions(map[string]interface{}{"rounds": opts.SHA512PasswdHashRounds}).Default().Salt(nil).Crypt([]byte(password)).String(), nil
}

func sha512CompareHash(password string, hash string) bool {
	var (
		crypter crypt.Crypter
		found   bool
	)

	crypter, found = crypt.SHA512.CrypterFound(hash)
	if found == false {
		return false
	}

	return crypter.Verify([]byte(password))
}

func CalcHash(password string, algo string) (string, error) {
	switch algo {
	case PasswdHashAlgoBCrypt:
		return bcryptCalcHash(password)

	case PasswdHashAlgoSHA512:
		return sha512CalcHash(password)
	}

	return "", errors.New("Unsupported password hash algorithm")
}

func CompareHash(password string, hash string, algo string) bool {
	switch algo {
	case PasswdHashAlgoBCrypt:
		return bcryptCompareHash(password, hash)

	case PasswdHashAlgoSHA512:
		return sha512CompareHash(password, hash)
	}

	return false
}

func CheckDifficulty(password string, diffOpt *DifficultyOpt) error {
	var (
		diffStat                 difficultyStat
		passwordAsRunes          []rune
		identicalyMap            map[rune]bool
		numberOfChecks           uint
		numberOfSuccessfulChecks uint
		errorsStack              []string
		resultError              string
	)

	identicalyMap = make(map[rune]bool)
	errorsStack = make([]string, 0)

	passwordAsRunes = []rune(password)
	diffStat.Length = len(passwordAsRunes)

	for _, char := range passwordAsRunes {
		if !identicalyMap[char] {
			identicalyMap[char] = true
			diffStat.EffectiveLength++
		}

		if unicode.IsLower(char) {
			diffStat.LowerCase++
			continue
		}

		if unicode.IsUpper(char) {
			diffStat.UpperCase++
			continue
		}

		if unicode.IsNumber(char) || unicode.IsDigit(char) {
			diffStat.Numbers++
			continue
		}

		if unicode.IsSymbol(char) || unicode.IsPunct(char) || unicode.IsMark(char) || unicode.IsSpace(char) {
			diffStat.Specials++
			continue
		}
	}

	if diffOpt.MinLength > 0 {
		numberOfChecks++

		if diffStat.Length >= diffOpt.MinLength {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password length is small")
		}
	}

	if diffOpt.DiffCase {
		numberOfChecks++

		if diffStat.LowerCase > 0 && diffStat.UpperCase > 0 {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password must contain characters in different registers")
		}
	}

	if diffOpt.Numbers {
		numberOfChecks++

		if diffStat.Numbers > 0 {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password must contain numbers")
		}
	}

	if diffOpt.Specials {
		numberOfChecks++

		if diffStat.Specials > 0 {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password must contain special characters")
		}
	}

	if diffOpt.MaxIdentSymPercent > 0 {
		numberOfChecks++

		if float32(diffStat.EffectiveLength) >= float32(diffStat.Length)-float32(diffStat.Length)*float32(diffOpt.MaxIdentSymPercent)/100.0 {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password contains many identical characters")
		}
	}

	if diffOpt.ForbidSequences > 0 {
		numberOfChecks++

		if findSequences(passwordAsRunes, diffOpt.ForbidSequences) == nil {
			numberOfSuccessfulChecks++
		} else {
			errorsStack = append(errorsStack, "Password contains typical sequences")
		}
	}

	if numberOfSuccessfulChecks == numberOfChecks {
		return nil
	} else {
		for index := range errorsStack {
			if resultError == "" {
				resultError = errorsStack[index]
			} else {
				resultError = resultError + "\n" + errorsStack[index]
			}
		}

		return errors.New(resultError)
	}

	return errors.New("Unknown error")
}
