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

package db

import (
	//"fmt"
	"errors"
	//"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

import (
	"github.com/akramarenkov/esam/src/data"
	"github.com/akramarenkov/esam/src/sqlqb"
)

const (
	DBMSTypeSQLite     = "sqlite"
	DBMSTypeMySQL      = "mysql"
	DBMSTypePostgreSQL = "postgres"
)

type Desc struct {
	dbmsType string
	dbName   string
	db       *sqlx.DB
}

func (desc *Desc) Connect(dbmsType string, dbmsAddr string, dbmsPort string, dbmsUser string, dbmsUserPassword string, dbName string) error {
	var (
		err        error
		descTmp    Desc
		driverName string
		dsn        string
	)

	switch dbmsType {
	case DBMSTypeSQLite:
		driverName = "sqlite3"

		if dbmsAddr != "" {
			dsn = "file:" + dbmsAddr
		} else {
			return errors.New("Path to the database file was not defined")
		}

	case DBMSTypeMySQL:
		driverName = "mysql"

		if dbName == "" {
			return errors.New("Database name was not specified")
		}

	case DBMSTypePostgreSQL:
		driverName = "postgres"

		if dbName == "" {
			return errors.New("Database name was not specified")
		}

	default:
		return errors.New("Unsupported DBMS was specified")
	}

	descTmp.dbmsType = dbmsType
	descTmp.dbName = dbName

	descTmp.db, err = sqlx.Connect(driverName, dsn)
	if err != nil {
		return err
	}

	(*desc) = descTmp

	return nil
}

func (desc *Desc) Init() error {
	var (
		err        error
		qb         sqlqb.QB
		access_req data.AccessReqDB
		user       data.UserDB
		node       data.NodeDB
	)

	switch desc.dbmsType {
	case DBMSTypeMySQL, DBMSTypePostgreSQL:
		_, err = desc.db.Exec(`CREATE DATABASE IF NOT EXISTS $1`, desc.dbName)
		if err != nil {
			return err
		}
	}

	err = qb.Begin(`CREATE TABLE IF NOT EXISTS access_reqs`, "db")
	if err != nil {
		return err
	}

	err = qb.ColumnsListFromStruct(access_req, "sqltype")
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX)
	if err != nil {
		return err
	}

	err = qb.Begin(`CREATE TABLE IF NOT EXISTS users`, "db")
	if err != nil {
		return err
	}

	err = qb.ColumnsListFromStruct(user, "sqltype")
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX)
	if err != nil {
		return err
	}

	err = qb.Begin(`CREATE TABLE IF NOT EXISTS nodes`, "db")
	if err != nil {
		return err
	}

	err = qb.ColumnsListFromStruct(node, "sqltype")
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) Test() error {
	var (
		err        error
		qb         sqlqb.QB
		access_req data.AccessReqDB
		user       data.UserDB
		node       data.NodeDB
	)

	err = qb.Begin(`SELECT`, "db")
	if err != nil {
		return err
	}

	err = qb.SelectListFromStruct(access_req, true)
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX + ` FROM access_reqs LIMIT 1`)
	if err != nil {
		return err
	}

	err = qb.Begin(`SELECT`, "db")
	if err != nil {
		return err
	}

	err = qb.SelectListFromStruct(user, true)
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX + ` FROM users LIMIT 1`)
	if err != nil {
		return err
	}

	err = qb.Begin(`SELECT`, "db")
	if err != nil {
		return err
	}

	err = qb.SelectListFromStruct(node, true)
	if err != nil {
		return err
	}

	_, err = desc.db.Exec(qb.QueryX + ` FROM nodes LIMIT 1`)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) GetAccessReqCount() (uint, error) {
	var (
		err   error
		count uint
	)

	err = desc.db.Get(&count, `SELECT COUNT(*) FROM access_reqs`)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (desc *Desc) AddAccessReq(access_req *data.AccessReqDB) error {
	var (
		err error
		qb  sqlqb.QB
	)

	err = qb.Begin(`INSERT INTO access_reqs`, "db")
	if err != nil {
		return err
	}

	err = qb.ValuesFromStruct(access_req)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, access_req)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) ListAccessReqs(filter *data.AccessReqDB) ([]data.AccessReqDB, error) {
	var (
		err  error
		qb   sqlqb.QB
		rows *sqlx.Rows
	)

	err = qb.Begin(`SELECT * FROM access_reqs`, "db")
	if err != nil {
		return nil, err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return nil, err
	}

	rows, err = desc.db.NamedQuery(qb.QueryX, qb.ArgsX)
	if err != nil {
		return nil, err
	}

	access_reqs := make([]data.AccessReqDB, 0)
	for rows.Next() {
		var access_req data.AccessReqDB

		err = rows.StructScan(&access_req)
		if err != nil {
			return nil, err
		}

		access_reqs = append(access_reqs, access_req)
	}

	return access_reqs, nil
}

func (desc *Desc) DelAccessReq(esamPubKey data.ESAMPubKey) error {
	var (
		err    error
		qb     sqlqb.QB
		filter data.AccessReqDB
	)

	filter.ESAMPubKey = esamPubKey

	err = qb.Begin(`DELETE FROM access_reqs`, "db")
	if err != nil {
		return err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, qb.ArgsX)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) AddUser(user *data.UserDB) error {
	var (
		err error
		qb  sqlqb.QB
	)

	err = qb.Begin(`INSERT INTO users`, "db")
	if err != nil {
		return err
	}

	err = qb.ValuesFromStruct(user)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, user)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) UpdateUser(filter *data.User, user *data.UserDB) error {
	var (
		err error
		qb  sqlqb.QB
	)

	err = qb.Begin(`UPDATE users`, "db")
	if err != nil {
		return err
	}

	err = qb.SetWhereFromStruct(user, filter, true)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, qb.ArgsX)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) ListUsers(filter *data.User) ([]data.UserDB, error) {
	var (
		err  error
		qb   sqlqb.QB
		rows *sqlx.Rows
	)

	err = qb.Begin(`SELECT * FROM users`, "db")
	if err != nil {
		return nil, err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return nil, err
	}

	rows, err = desc.db.NamedQuery(qb.QueryX, qb.ArgsX)
	if err != nil {
		return nil, err
	}

	users := make([]data.UserDB, 0)
	for rows.Next() {
		var user data.UserDB

		err = rows.StructScan(&user)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (desc *Desc) DelUser(esamPubKey data.ESAMPubKey) error {
	var (
		err    error
		qb     sqlqb.QB
		filter data.User
	)

	filter.ESAMPubKey = esamPubKey

	err = qb.Begin(`DELETE FROM users`, "db")
	if err != nil {
		return err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, qb.ArgsX)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) AddNode(node *data.NodeDB) error {
	var (
		err error
		qb  sqlqb.QB
	)

	err = qb.Begin(`INSERT INTO nodes`, "db")
	if err != nil {
		return err
	}

	err = qb.ValuesFromStruct(node)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, node)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) UpdateNode(filter *data.Node, node *data.NodeDB) error {
	var (
		err error
		qb  sqlqb.QB
	)

	err = qb.Begin(`UPDATE nodes`, "db")
	if err != nil {
		return err
	}

	err = qb.SetWhereFromStruct(node, filter, true)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, qb.ArgsX)
	if err != nil {
		return err
	}

	return nil
}

func (desc *Desc) ListNodes(filter *data.Node) ([]data.NodeDB, error) {
	var (
		err  error
		qb   sqlqb.QB
		rows *sqlx.Rows
	)

	err = qb.Begin(`SELECT * FROM nodes`, "db")
	if err != nil {
		return nil, err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return nil, err
	}

	rows, err = desc.db.NamedQuery(qb.QueryX, qb.ArgsX)
	if err != nil {
		return nil, err
	}

	nodes := make([]data.NodeDB, 0)
	for rows.Next() {
		var node data.NodeDB

		err = rows.StructScan(&node)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

func (desc *Desc) DelNode(esamPubKey data.ESAMPubKey) error {
	var (
		err    error
		qb     sqlqb.QB
		filter data.Node
	)

	filter.ESAMPubKey = esamPubKey

	err = qb.Begin(`DELETE FROM nodes`, "db")
	if err != nil {
		return err
	}

	err = qb.WhereAndFromStruct(filter)
	if err != nil {
		return err
	}

	_, err = desc.db.NamedExec(qb.QueryX, qb.ArgsX)
	if err != nil {
		return err
	}

	return nil
}
