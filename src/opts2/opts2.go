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

package opts2

import (
	"github.com/akramarenkov/esam/src/passwd"
)

const (
	PasswdHashAlgo = passwd.PasswdHashAlgoSHA512
)

var (
	PasswdDifficulty = passwd.DifficultyOpt{
		MinLength:          14,
		DiffCase:           true,
		Numbers:            true,
		Specials:           true,
		MaxIdentSymPercent: 20,
		ForbidSequences:    4,
	}
)
