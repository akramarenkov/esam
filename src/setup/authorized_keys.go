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

package setup

import (
	"errors"
	"io"
	"os"
	"os/user"
	"path"
)

import (
	"github.com/akramarenkov/esam/src/opts"
	"github.com/akramarenkov/esam/src/types"
)

func AuthorizedKeyPresent(userName string, authKeyIn *types.AuthorizedKey, exclusive bool) error {
	var (
		err              error
		authKey          *types.AuthorizedKey
		userInfo         *user.User
		sshDirPath       string
		authKeysFilePath string
		authKeysFile     *os.File
		authKeys         []types.AuthorizedKey
	)

	if authKeyIn == nil {
		return errors.New("Authorized key pointer can't be nil")
	}

	authKey, err = authKeyIn.Copy()
	if err != nil {
		return err
	}

	err = authKey.Normalize()
	if err != nil {
		return err
	}

	userInfo, err = user.Lookup(userName)
	if err != nil {
		return err
	}

	sshDirPath = path.Join(userInfo.HomeDir, opts.SSHDirName)
	authKeysFilePath = path.Join(sshDirPath, opts.AuthorizedKeysFileName)

	err = DirPresent(sshDirPath, opts.SSHDirMode, userInfo.Uid, userInfo.Gid)
	if err != nil {
		return err
	}

	authKeysFile, err = FilePresent(authKeysFilePath, opts.AuthorizedKeysFileMode, userInfo.Uid, userInfo.Gid)
	if err != nil {
		return err
	}
	defer authKeysFile.Close()

	if exclusive {
		authKeys = make([]types.AuthorizedKey, 0)
		authKeys = append(authKeys, (*authKey))
	} else {
		authKeys, err = types.AuthorizedKeysFromFile(authKeysFile)
		if err != nil {
			return err
		}

		authKeysTmp := make([]types.AuthorizedKey, 0)

		for index := range authKeys {
			if authKeys[index].Key != authKey.Key {
				authKeysTmp = append(authKeysTmp, authKeys[index])
			}
		}

		authKeysTmp = append(authKeysTmp, (*authKey))

		authKeys = authKeysTmp
	}

	err = authKeysFile.Truncate(0)
	if err != nil {
		return err
	}

	_, err = authKeysFile.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = types.AuthorizedKeysToFile(authKeysFile, authKeys)
	if err != nil {
		return err
	}

	return nil
}

func AuthorizedKeyAbsent(userName string, authKeyIn *types.AuthorizedKey, all bool) error {
	var (
		err              error
		authKey          *types.AuthorizedKey
		userInfo         *user.User
		sshDirPath       string
		authKeysFilePath string
		authKeysFile     *os.File
		authKeys         []types.AuthorizedKey
		authKeysTmp      []types.AuthorizedKey
	)

	if !all {
		if authKeyIn == nil {
			return errors.New("Authorized key pointer can't be nil")
		}

		authKey, err = authKeyIn.Copy()
		if err != nil {
			return err
		}

		err = authKey.Normalize()
		if err != nil {
			return err
		}
	}

	userInfo, err = user.Lookup(userName)
	if err != nil {
		return err
	}

	sshDirPath = path.Join(userInfo.HomeDir, opts.SSHDirName)
	authKeysFilePath = path.Join(sshDirPath, opts.AuthorizedKeysFileName)

	err = DirPresent(sshDirPath, opts.SSHDirMode, userInfo.Uid, userInfo.Gid)
	if err != nil {
		return err
	}

	authKeysFile, err = FilePresent(authKeysFilePath, opts.AuthorizedKeysFileMode, userInfo.Uid, userInfo.Gid)
	if err != nil {
		return err
	}
	defer authKeysFile.Close()

	if !all {
		authKeys, err = types.AuthorizedKeysFromFile(authKeysFile)
		if err != nil {
			return err
		}

		authKeysTmp = make([]types.AuthorizedKey, 0)

		for index := range authKeys {
			if authKeys[index].Key != authKey.Key {
				authKeysTmp = append(authKeysTmp, authKeys[index])
			}
		}

		authKeys = authKeysTmp
	}

	err = authKeysFile.Truncate(0)
	if err != nil {
		return err
	}

	_, err = authKeysFile.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	if !all {
		err = types.AuthorizedKeysToFile(authKeysFile, authKeys)
		if err != nil {
			return err
		}
	}

	return nil
}
