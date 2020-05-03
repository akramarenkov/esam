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

package netapi

import (
	"encoding/json"
	"errors"
)

import (
	"github.com/akramarenkov/esam/src/data"
)

/*
{ "msg": { "type": "request", "request": "get_dir_conn_settings" } }
{ "msg": { "type": "reply", "request": "get_dir_conn_settings" }, "result": { "status": "failed", "reason": "" } }
{ "msg": { "type": "reply", "request": "get_dir_conn_settings" }, "result": { "status": "successful", "reason": "" }, "dir_conn_settings": { "esam_key_path": "", "dir_addr": "", "dir_port": "", "tls_ca_cert_path": "", "verify_key_path": "" } }
*/

/* For build and parse request use BuildSimpleReq and ParseMsgHeader functions */

type repGetDirConnSettings struct {
	msgHeaderWrapper
	reqResultWrapper
	Settings data.DirConnSettings `json:"dir_conn_settings"`
}

func BuildRepGetDirConnSettings(dirConnSettingsIn *data.DirConnSettings) ([]byte, error) {
	var err error
	var rep []byte
	var repGetDirConnSettings repGetDirConnSettings

	repGetDirConnSettings.MsgHeader.Type = MsgTypeReply
	repGetDirConnSettings.MsgHeader.SubType = ReqTypeGetDirConnSettings
	repGetDirConnSettings.ReqResult.Status = ReqResultStatusSuccessful
	repGetDirConnSettings.ReqResult.Reason = ReqResultReasonEmpty
	repGetDirConnSettings.Settings = (*dirConnSettingsIn)

	rep, err = json.Marshal(repGetDirConnSettings)
	if err != nil {
		return nil, err
	}

	return rep[:], nil
}

func ParseRepGetDirConnSettings(jsonIn []byte, dirConnSettingsOut *data.DirConnSettings) error {
	var err error
	var repGetDirConnSettings repGetDirConnSettings

	err = json.Unmarshal(jsonIn[:], &repGetDirConnSettings)
	if err != nil {
		return err
	}

	if repGetDirConnSettings.MsgHeader.Type != MsgTypeReply {
		return errors.New("Unexpected message type")
	}

	if repGetDirConnSettings.MsgHeader.SubType != ReqTypeGetDirConnSettings {
		return errors.New("Unexpected request type")
	}

	err = repGetDirConnSettings.ReqResult.Test()
	if err != nil {
		return err
	}

	(*dirConnSettingsOut) = repGetDirConnSettings.Settings

	return nil
}
