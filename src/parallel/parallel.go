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

package parallel

import (
	"runtime"
	"sync"
)

import (
	"esam/src/auth"
	"esam/src/data"
	"esam/src/types"
)

func MakeUserAuthList(usersListDB []data.UserDB, verifyKey *data.ESAMPubKey, coresRatio float32) ([]data.UserAuth, error) {
	var err error

	var usersList []data.UserAuth
	var trustedData bool

	var numberOfSteps int
	var stepLength int
	var waitCheck sync.WaitGroup

	usersList = make([]data.UserAuth, len(usersListDB[:]))

	listConv := func(beginIndex int, endIndex int, wait *sync.WaitGroup) {
		defer wait.Done()

		for index := beginIndex; index <= endIndex; index++ {
			usersList[index].User = usersListDB[index].User
			usersList[index].TrustedData = types.False

			if verifyKey != nil {
				trustedData, err = auth.CheckUserDataAuthenticity(&usersListDB[index], usersListDB[:], verifyKey)
				if err == nil && trustedData {
					usersList[index].TrustedData = types.True
				} else {
					usersList[index].TrustedData = types.False
				}
			}
		}
	}

	numberOfSteps = int(float32(runtime.NumCPU()) * coresRatio)
	if numberOfSteps == 0 {
		numberOfSteps = 1
	}

	stepLength = len(usersListDB[:]) / numberOfSteps

	if stepLength == 0 {
		stepLength = 1
	}

	for stepIndex := 0; stepIndex < numberOfSteps; stepIndex++ {
		var beginIndex int
		var endIndex int

		beginIndex = stepIndex * stepLength

		if stepIndex == numberOfSteps-1 {
			endIndex = len(usersListDB[:]) - 1
		} else {
			endIndex = (stepIndex+1)*stepLength - 1
		}

		if endIndex > len(usersListDB[:])-1 {
			break
		}

		waitCheck.Add(1)

		go listConv(beginIndex, endIndex, &waitCheck)
	}

	waitCheck.Wait()

	return usersList[:], nil
}

func MakeNodeAuthList(nodesListDB []data.NodeDB, usersListDB []data.UserDB, verifyKey *data.ESAMPubKey, coresRatio float32) ([]data.NodeAuth, error) {
	var err error

	var nodesList []data.NodeAuth
	var trustedData bool

	var numberOfSteps int
	var stepLength int
	var waitCheck sync.WaitGroup

	nodesList = make([]data.NodeAuth, len(nodesListDB[:]))

	listConv := func(beginIndex int, endIndex int, wait *sync.WaitGroup) {
		defer wait.Done()

		for index := beginIndex; index <= endIndex; index++ {
			nodesList[index].Node = nodesListDB[index].Node
			nodesList[index].TrustedData = types.False

			if verifyKey != nil {
				trustedData, err = auth.CheckNodeDataAuthenticity(&nodesListDB[index], usersListDB[:], verifyKey)
				if err == nil && trustedData {
					nodesList[index].TrustedData = types.True
				}
			}
		}
	}

	numberOfSteps = int(float32(runtime.NumCPU()) * coresRatio)
	if numberOfSteps == 0 {
		numberOfSteps = 1
	}

	stepLength = len(nodesListDB[:]) / numberOfSteps

	if stepLength == 0 {
		stepLength = 1
	}

	for stepIndex := 0; stepIndex < numberOfSteps; stepIndex++ {
		var beginIndex int
		var endIndex int

		beginIndex = stepIndex * stepLength

		if stepIndex == numberOfSteps-1 {
			endIndex = len(nodesListDB[:]) - 1
		} else {
			endIndex = (stepIndex+1)*stepLength - 1
		}

		if endIndex > len(nodesListDB[:])-1 {
			break
		}

		waitCheck.Add(1)

		go listConv(beginIndex, endIndex, &waitCheck)
	}

	waitCheck.Wait()

	return nodesList[:], nil
}
