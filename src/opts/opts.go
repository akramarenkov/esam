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

package opts

import (
  "time"
  "crypto/tls"
  "os"
)

const (
  KeySize = 4096
  MinAuthQuestionSize = 256
  TLSMinVersion = tls.VersionTLS13
  NetMaxMsgSize uint64 = 1024*1024*1024
  NetTimeout = 5 * time.Second
  NoopNoticePeriod = NetTimeout
  NoMsgThresholdTime = 12 * NoopNoticePeriod
  BCryptPasswdHashCost = 12
  SHA512PasswdHashRounds = 10000
  AccessReqListLimit = 50
  UIPageSize = 3
  DelayBeforeSendErrorReplyInUnAuthConn = 2 * NetTimeout
  CPUUtilizationFactor = 0.25
  ReconnectPause = 2 * time.Second
  UpdateNodesCachePeriod = 1800 * time.Second
  UpdateUsersListPeriod = 1800 * time.Second
  UsersSetupPeriod = 1800 * time.Second
  DataEventChanCapacity = 1024
  DataEventLifeTime = 60 * time.Second
  SessionCloserPeriod = 1 * time.Second
  CommandTimeout = 5 * time.Second
  UsersGroup = "esam"
  SSHDirName = ".ssh"
  SSHDirMode = os.ModeDir | 0700
  AuthorizedKeysFileName = "authorized_keys"
  AuthorizedKeysFileMode = 0600
  UserShell = "/bin/bash"
)

var (
  ElevatePrivilegesGroups = []string{ "sudo", "adm", "wheel" }
)
