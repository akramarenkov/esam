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

package sqlqb

import (
	"fmt"
	"os"
	"testing"
)

type User struct {
	ESAMPubKey        []byte `db:"esam_pub_key" sqltype:"VARBINARY(6144) NOT NULL PRIMARY KEY"`
	Name              string `db:"name" sqltype:"CHAR(63) NOT NULL UNIQUE"`
	ElevatePrivileges bool   `db:"elevate_privileges" sqltype:"BOOLEAN"`
}

type UserSign struct {
	ESAMPubKeySign        []byte `db:"esam_pub_key_sign" sqltype:"VARBINARY(4096)"`
	NameSign              []byte `db:"name_sign" sqltype:"VARBINARY(4096)"`
	ElevatePrivilegesSign []byte `db:"elevate_privileges_sign" sqltype:"VARBINARY(4096)"`
	SignSubject           []byte `db:"sign_subject" sqltype:"VARBINARY(6144)"`
}

type UserDB struct {
	User
	UserSign
}

func Test(t *testing.T) {
	var err error
	var qb QB
	var user User
	var userDB UserDB

	fmt.Printf("\n*********** ColumnsListFromStruct\n")

	err = qb.Begin(`CREATE TABLE IF NOT EXISTS users`, "db")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed Begin", err)
		os.Exit(1)
	}

	err = qb.ColumnsListFromStruct(userDB, "sqltype")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed ColumnsListFromStruct", err)
		os.Exit(1)
	}

	fmt.Printf("qb.Query = \n%+v\nqb.QueryX = \n%+v\nqb.Args = \n%+v\nqb.ArgsX = \n%+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)

	fmt.Printf("\n*********** SelectListFromStruct\n")

	err = qb.Begin(`SELECT`, "db")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed Begin", err)
		os.Exit(1)
	}

	err = qb.SelectListFromStruct(userDB, true)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed SelectListFromStruct", err)
		os.Exit(1)
	}

	fmt.Printf("qb.Query = \n%+v\nqb.QueryX = \n%+v\nqb.Args = \n%+v\nqb.ArgsX = \n%+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)

	fmt.Printf("\n*********** ValuesFromStruct\n")

	err = qb.Begin(`INSERT INTO users`, "db")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed Begin", err)
		os.Exit(1)
	}

	err = qb.ValuesFromStruct(userDB)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed ValuesFromStruct", err)
		os.Exit(1)
	}

	fmt.Printf("qb.Query = \n%+v\nqb.QueryX = \n%+v\nqb.Args = \n%+v\nqb.ArgsX = \n%+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)

	/* Used as filter */
	user = User{
		ESAMPubKey:        []byte("ESAMPubKey data"),
		Name:              "owner",
		ElevatePrivileges: true,
	}

	userDB = UserDB{
		User: User{
			ESAMPubKey:        []byte("ESAMPubKey new data"),
			Name:              "owner_new",
			ElevatePrivileges: false,
		},
	}

	fmt.Printf("\n*********** SetWhereFromStruct\n")

	err = qb.Begin(`UPDATE users`, "db")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed Begin", err)
		os.Exit(1)
	}

	err = qb.SetWhereFromStruct(userDB, user, true)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed SetWhereFromStruct", err)
		os.Exit(1)
	}

	fmt.Printf("qb.Query = \n%+v\nqb.QueryX = \n%+v\nqb.Args = \n%+v\nqb.ArgsX = \n%+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)

	fmt.Printf("\n*********** WhereAndFromStruct\n")

	err = qb.Begin(`SELECT * FROM users`, "db")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed Begin", err)
		os.Exit(1)
	}

	err = qb.WhereAndFromStruct(user)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed WhereAndFromStruct", err)
		os.Exit(1)
	}

	fmt.Printf("qb.Query = \n%+v\nqb.QueryX = \n%+v\nqb.Args = \n%+v\nqb.ArgsX = \n%+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)

}
