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

/* ToleratesEmptyFieldsYes used when using structures as filters */
const (
	ToleratesEmptyFieldsYes = true
	ToleratesEmptyFieldsNo  = false
)

/* Signing process constants */
const (
	ESAMPubKeyFieldName  = "ESAMPubKey"
	SignSubjectFieldName = "SignSubject"
	signFieldSuffix      = "Sign"
)

type Tester interface {
	Test(bool) error
}
