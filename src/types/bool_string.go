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

package types

import (
  "errors"
  "strings"
  "sort"
)

const (
  True = "true"
  False = "false"
)

var (
  boolStringValues = map[string]string {
    True: True,
    False: False,
  }
)

func NormalizeBoolString(boolString string) (string) {
  return strings.TrimSpace(boolString)
}

func TestBoolString(boolString string, toleratesEmptyFields bool) (error) {
  if toleratesEmptyFields && len(boolString) == 0 {
    return nil
  }
  
  if boolStringValues[boolString] == "" {
    return errors.New("Unsupported bool type value")
  }
  
  return nil
}

func TemplateBoolString() (string) {
  var list []string
  
  list = make([]string, 0)
  
  for _, item := range boolStringValues {
    list = append(list, item)
  }
  
  sort.Strings(list)
  
  return strings.Join(list, " | ")
}
