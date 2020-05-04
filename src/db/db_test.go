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
	"fmt"
	"os"
	"testing"
	"time"
)

import (
	"github.com/akramarenkov/esam/src/data"
)

import (
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbFile = "test.db"
)

func Test(t *testing.T) {
	var (
		err error
		db  Desc
	)

	os.Remove(dbFile)

	err = db.Connect("sqlite", dbFile, "", "", "", "")
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to open database", err)
		os.Exit(1)
	}

	err = db.Init()
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to init database", err)
		os.Exit(1)
	}

	err = db.Test()
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to test database", err)
		os.Exit(1)
	}

	/* AccessReq */

	var (
		accessReqFilter data.AccessReqDB
		accessReqs      []data.AccessReqDB
		newAccessReq    data.AccessReqDB
	)

	newAccessReq = data.AccessReqDB{
		data.AccessReq{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
			Subject: data.AccessReqSubjectUser,
			Name:    "newUser",
		},

		data.AccessReqInner{
			Addr: "127.0.0.1",
			Time: time.Now(),
		},
	}

	err = db.AddAccessReq(&newAccessReq)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add access request", err)
		os.Exit(1)
	}

	newAccessReq = data.AccessReqDB{
		data.AccessReq{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1UR2yOALzQyLqHc4X+zs
zLDPJxA+kMEOukdsa0kgZlb2bMMXc7s/V6Jn5Lkk4F/vIT4ETKwsLGwX05y2CawZ
S3As7ipyvLZSOciAU20rXjrWFHjMoRcKlw1iGE76wDTBarjLq+gUHtYe15XBON6w
I0fp4CdrxkeR0CmV2cYihsonEoThQSQJjVPx9g8aslQ/0Lc/6N9Yw4UY0OILmf2U
P+3tTickZgE9bKrBNc1V4AyHpmK+XK2FnaP1Ep3hoOaCVqXZiMpR/kDFCPkuMbYB
GyoplFsBvh2ER4NkIlkaR2KKrOiLr/AKs3ILBx5Xmu1FXpdTCKkkSIZpKsK/757v
T/Cla4NG6hlbWWVtkU421h99IoGULfAwWp3FYCNR0vL3Je3VLVtStCsJlN+MiCmo
U24YUk3K1zPo9YBIUNqn3tsEHUzhUfSU5klNfQ536aDfzWGGGxVjczd/a6ImTF3T
tKkdqBpsgDwWH2/GxKNOFOsz6z0aV5wd7zr2uJuE8QQO96YBNc6wFTEpFXYAdthl
9sLgNaHMuFl0ygEy09nqXsT7nqJEFKs5OfUBkQB9wtJkMhWODHO3OSSwDIlU1CbW
MFfEXB9N1YZ41wRkysdeNGGewceP9K5Q3K+Szu3gaBsqNiOluJZ7tAW2XyAWTtPv
1e+8OAQ3faYXeL0Ow81iNW0CAwEAAQ==
-----END PUBLIC KEY-----`),
			Subject: data.AccessReqSubjectAgent,
			Name:    "hv-1",
		},

		data.AccessReqInner{
			Addr: "127.0.0.1",
			Time: time.Now(),
		},
	}

	err = db.AddAccessReq(&newAccessReq)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add access request", err)
		os.Exit(1)
	}

	/* The effect of zeroing is the same */
	accessReqFilter = data.AccessReqDB{
		data.AccessReq{
			ESAMPubKey: []byte{},
			Subject:    "",
			Name:       "",
		},
		data.AccessReqInner{
			Addr: "",
			Time: time.Time{},
		},
	}

	accessReqFilter = data.AccessReqDB{
		data.AccessReq{},
		data.AccessReqInner{},
	}

	fmt.Printf("*********************** %v\n", "1")

	accessReqs, err = db.ListAccessReqs(&accessReqFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list access requests", err)
		os.Exit(1)
	}

	if len(accessReqs) != 2 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", accessReqs)

	accessReqFilter = data.AccessReqDB{
		data.AccessReq{
			Subject: data.AccessReqSubjectAgent,
		},
		data.AccessReqInner{},
	}

	fmt.Printf("*********************** %v\n", "2")

	accessReqs, err = db.ListAccessReqs(&accessReqFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list access requests", err)
		os.Exit(1)
	}

	if len(accessReqs) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", accessReqs)

	accessReqFilter = data.AccessReqDB{
		data.AccessReq{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
		},
		data.AccessReqInner{},
	}

	fmt.Printf("*********************** %v\n", "3")

	accessReqs, err = db.ListAccessReqs(&accessReqFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list access requests", err)
		os.Exit(1)
	}

	if len(accessReqs) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", accessReqs)

	for _, accessReq := range accessReqs {
		err = db.DelAccessReq(accessReq.ESAMPubKey)
		if err != nil {
			fmt.Printf("%v. Details: %v\n", "Failed to delete access request", err)
			os.Exit(1)
		}
	}

	fmt.Printf("*********************** %v\n", "4")

	accessReqs, err = db.ListAccessReqs(&accessReqFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list access requests", err)
		os.Exit(1)
	}

	if len(accessReqs) != 0 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	/* User */

	var (
		userFilter data.User
		users      []data.UserDB
		newUser    data.UserDB
	)

	newUser = data.UserDB{
		data.User{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
			Name:              "newSecAdmin",
			Role:              data.UserRoleSecAdmin,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key sec admin",
			PasswordHash:      "password hash sec admin",
			ElevatePrivileges: true,
		},
		data.UserSign{
			SignSubject: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
		},
	}

	err = db.AddUser(&newUser)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add user", err)
		os.Exit(1)
	}

	newUser = data.UserDB{
		data.User{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1UR2yOALzQyLqHc4X+zs
zLDPJxA+kMEOukdsa0kgZlb2bMMXc7s/V6Jn5Lkk4F/vIT4ETKwsLGwX05y2CawZ
S3As7ipyvLZSOciAU20rXjrWFHjMoRcKlw1iGE76wDTBarjLq+gUHtYe15XBON6w
I0fp4CdrxkeR0CmV2cYihsonEoThQSQJjVPx9g8aslQ/0Lc/6N9Yw4UY0OILmf2U
P+3tTickZgE9bKrBNc1V4AyHpmK+XK2FnaP1Ep3hoOaCVqXZiMpR/kDFCPkuMbYB
GyoplFsBvh2ER4NkIlkaR2KKrOiLr/AKs3ILBx5Xmu1FXpdTCKkkSIZpKsK/757v
T/Cla4NG6hlbWWVtkU421h99IoGULfAwWp3FYCNR0vL3Je3VLVtStCsJlN+MiCmo
U24YUk3K1zPo9YBIUNqn3tsEHUzhUfSU5klNfQ536aDfzWGGGxVjczd/a6ImTF3T
tKkdqBpsgDwWH2/GxKNOFOsz6z0aV5wd7zr2uJuE8QQO96YBNc6wFTEpFXYAdthl
9sLgNaHMuFl0ygEy09nqXsT7nqJEFKs5OfUBkQB9wtJkMhWODHO3OSSwDIlU1CbW
MFfEXB9N1YZ41wRkysdeNGGewceP9K5Q3K+Szu3gaBsqNiOluJZ7tAW2XyAWTtPv
1e+8OAQ3faYXeL0Ow81iNW0CAwEAAQ==
-----END PUBLIC KEY-----`),
			Name:              "newOwner",
			Role:              data.UserRoleOwner,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key owner",
			PasswordHash:      "password hash owner",
			ElevatePrivileges: true,
		},
		data.UserSign{
			SignSubject: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1UR2yOALzQyLqHc4X+zs
zLDPJxA+kMEOukdsa0kgZlb2bMMXc7s/V6Jn5Lkk4F/vIT4ETKwsLGwX05y2CawZ
S3As7ipyvLZSOciAU20rXjrWFHjMoRcKlw1iGE76wDTBarjLq+gUHtYe15XBON6w
I0fp4CdrxkeR0CmV2cYihsonEoThQSQJjVPx9g8aslQ/0Lc/6N9Yw4UY0OILmf2U
P+3tTickZgE9bKrBNc1V4AyHpmK+XK2FnaP1Ep3hoOaCVqXZiMpR/kDFCPkuMbYB
GyoplFsBvh2ER4NkIlkaR2KKrOiLr/AKs3ILBx5Xmu1FXpdTCKkkSIZpKsK/757v
T/Cla4NG6hlbWWVtkU421h99IoGULfAwWp3FYCNR0vL3Je3VLVtStCsJlN+MiCmo
U24YUk3K1zPo9YBIUNqn3tsEHUzhUfSU5klNfQ536aDfzWGGGxVjczd/a6ImTF3T
tKkdqBpsgDwWH2/GxKNOFOsz6z0aV5wd7zr2uJuE8QQO96YBNc6wFTEpFXYAdthl
9sLgNaHMuFl0ygEy09nqXsT7nqJEFKs5OfUBkQB9wtJkMhWODHO3OSSwDIlU1CbW
MFfEXB9N1YZ41wRkysdeNGGewceP9K5Q3K+Szu3gaBsqNiOluJZ7tAW2XyAWTtPv
1e+8OAQ3faYXeL0Ow81iNW0CAwEAAQ==
-----END PUBLIC KEY-----`),
		},
	}

	err = db.AddUser(&newUser)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add user", err)
		os.Exit(1)
	}

	userFilter = data.User{
		Name:      "newSecAdmin",
		SSHPubKey: "SSH public key sec admin",
	}

	fmt.Printf("*********************** %v\n", "1")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", users)

	userFilter = data.User{
		Name:      "newSecAdmin",
		SSHPubKey: "SSH public key",
	}

	fmt.Printf("*********************** %v\n", "2")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 0 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", users)

	userFilter = data.User{}

	fmt.Printf("*********************** %v\n", "3")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 2 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", users)

	for _, user := range users {
		var userFilter data.User

		userFilter.ESAMPubKey = user.ESAMPubKey

		user.Name = user.Name + " updated"

		err = db.UpdateUser(&userFilter, &user)
		if err != nil {
			fmt.Printf("%v. Details: %v\n", "Failed to update user", err)
			os.Exit(1)
		}
	}

	userFilter = data.User{}

	fmt.Printf("*********************** %v\n", "4")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 2 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", users)

	userFilter = data.User{
		ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
	}

	fmt.Printf("*********************** %v\n", "5")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", users)

	userFilter = data.User{}

	fmt.Printf("*********************** %v\n", "6")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	for _, user := range users {
		err = db.DelUser(user.ESAMPubKey)
		if err != nil {
			fmt.Printf("%v. Details: %v\n", "Failed to delete user", err)
			os.Exit(1)
		}
	}

	userFilter = data.User{}

	fmt.Printf("*********************** %v\n", "7")

	users, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list users", err)
		os.Exit(1)
	}

	if len(users) != 0 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	/* Node */

	var (
		nodeFilter data.Node
		nodes      []data.NodeDB
		newNode    data.NodeDB
	)

	newNode = data.NodeDB{
		data.Node{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
			Name:    "newNode1",
			SSHAddr: "SSH addr",
			SSHPort: "22",
		},
		data.NodeSign{
			SignSubject: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
		},
	}

	err = db.AddNode(&newNode)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add node", err)
		os.Exit(1)
	}

	newNode = data.NodeDB{
		data.Node{
			ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1UR2yOALzQyLqHc4X+zs
zLDPJxA+kMEOukdsa0kgZlb2bMMXc7s/V6Jn5Lkk4F/vIT4ETKwsLGwX05y2CawZ
S3As7ipyvLZSOciAU20rXjrWFHjMoRcKlw1iGE76wDTBarjLq+gUHtYe15XBON6w
I0fp4CdrxkeR0CmV2cYihsonEoThQSQJjVPx9g8aslQ/0Lc/6N9Yw4UY0OILmf2U
P+3tTickZgE9bKrBNc1V4AyHpmK+XK2FnaP1Ep3hoOaCVqXZiMpR/kDFCPkuMbYB
GyoplFsBvh2ER4NkIlkaR2KKrOiLr/AKs3ILBx5Xmu1FXpdTCKkkSIZpKsK/757v
T/Cla4NG6hlbWWVtkU421h99IoGULfAwWp3FYCNR0vL3Je3VLVtStCsJlN+MiCmo
U24YUk3K1zPo9YBIUNqn3tsEHUzhUfSU5klNfQ536aDfzWGGGxVjczd/a6ImTF3T
tKkdqBpsgDwWH2/GxKNOFOsz6z0aV5wd7zr2uJuE8QQO96YBNc6wFTEpFXYAdthl
9sLgNaHMuFl0ygEy09nqXsT7nqJEFKs5OfUBkQB9wtJkMhWODHO3OSSwDIlU1CbW
MFfEXB9N1YZ41wRkysdeNGGewceP9K5Q3K+Szu3gaBsqNiOluJZ7tAW2XyAWTtPv
1e+8OAQ3faYXeL0Ow81iNW0CAwEAAQ==
-----END PUBLIC KEY-----`),
			Name:    "newNode2",
			SSHAddr: "SSH addr",
			SSHPort: "2222",
		},
		data.NodeSign{
			SignSubject: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1UR2yOALzQyLqHc4X+zs
zLDPJxA+kMEOukdsa0kgZlb2bMMXc7s/V6Jn5Lkk4F/vIT4ETKwsLGwX05y2CawZ
S3As7ipyvLZSOciAU20rXjrWFHjMoRcKlw1iGE76wDTBarjLq+gUHtYe15XBON6w
I0fp4CdrxkeR0CmV2cYihsonEoThQSQJjVPx9g8aslQ/0Lc/6N9Yw4UY0OILmf2U
P+3tTickZgE9bKrBNc1V4AyHpmK+XK2FnaP1Ep3hoOaCVqXZiMpR/kDFCPkuMbYB
GyoplFsBvh2ER4NkIlkaR2KKrOiLr/AKs3ILBx5Xmu1FXpdTCKkkSIZpKsK/757v
T/Cla4NG6hlbWWVtkU421h99IoGULfAwWp3FYCNR0vL3Je3VLVtStCsJlN+MiCmo
U24YUk3K1zPo9YBIUNqn3tsEHUzhUfSU5klNfQ536aDfzWGGGxVjczd/a6ImTF3T
tKkdqBpsgDwWH2/GxKNOFOsz6z0aV5wd7zr2uJuE8QQO96YBNc6wFTEpFXYAdthl
9sLgNaHMuFl0ygEy09nqXsT7nqJEFKs5OfUBkQB9wtJkMhWODHO3OSSwDIlU1CbW
MFfEXB9N1YZ41wRkysdeNGGewceP9K5Q3K+Szu3gaBsqNiOluJZ7tAW2XyAWTtPv
1e+8OAQ3faYXeL0Ow81iNW0CAwEAAQ==
-----END PUBLIC KEY-----`),
		},
	}

	err = db.AddNode(&newNode)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to add node", err)
		os.Exit(1)
	}

	nodeFilter = data.Node{
		Name:    "newNode1",
		SSHPort: "22",
	}

	fmt.Printf("*********************** %v\n", "1")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", nodes)

	nodeFilter = data.Node{
		Name:    "newNode1",
		SSHPort: "2222",
	}

	fmt.Printf("*********************** %v\n", "2")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 0 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", nodes)

	nodeFilter = data.Node{}

	fmt.Printf("*********************** %v\n", "3")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 2 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", nodes)

	for _, node := range nodes {
		var nodeFilter data.Node

		nodeFilter.ESAMPubKey = node.ESAMPubKey

		node.Name = node.Name + " updated"

		err = db.UpdateNode(&nodeFilter, &node)
		if err != nil {
			fmt.Printf("%v. Details: %v\n", "Failed to update node", err)
			os.Exit(1)
		}
	}

	nodeFilter = data.Node{}

	fmt.Printf("*********************** %v\n", "4")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 2 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", nodes)

	nodeFilter = data.Node{
		ESAMPubKey: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArh/5enS67Z7OToGzvuEW
wAZqVXe3ZK9aqlRwmz23uQx3u1uXz3cbjDiwjwCXQDpTg6TK6MVKz1AcAupHhOBg
l5IsziqwQkQRY+JjNYW8Cdp7Y35rbzYfbxmmX911oYLvegXgnoJAIHoEuH6OkuZo
VjM8PLxlgLLDXOrWUNE/V3Xd3FbOlUIYXQ5pww6KVFP6yNYEh1Kx6WyNTfjAcyhT
EVv5wbgx3X9qKRrEQT9jJjP0d+9D//x0n4vm+KzTyqty6D824VknNN0SgYOPVb4h
CHGxPKOf7vcqIEaMZNRcH8HcnTug4LF6oUvUe6TbDB43xpNYrUjq1wzvZJDt3TxI
oJOa2jB5c+cGLInkd+HunD7njQ68MkNxFm0P7m+mDrdBWAQCXhakBu+fMYIep8hC
eTu6DBXBjISPeDrP6ji71CeNRq+YRY1ZEdIUXOg9faMiIVP9pkGhoUtNaj10PUgv
cSQ7TeJPFYCoKGwjdrKz5otXKd/6JzGjPsGiEXQv2zjt3Wc2vdSNga800NWFe5y5
19IxMazpP/tI/tmrBGjWSz1Zn7dUd6oy/f7o3sR9CORXJt9IMGRdwOxyCMXi1c5/
2qXTNBxEutBYs6ia6YwK+/KjpLFY1XI7K9UCaunseyp/M0UYOPjgSHd2GtqmsXyz
f8+H9tvQ3n7mgb6nHERBNPUCAwEAAQ==
-----END PUBLIC KEY-----`),
	}

	fmt.Printf("*********************** %v\n", "5")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 1 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	fmt.Printf("%v\n", nodes)

	nodeFilter = data.Node{}

	fmt.Printf("*********************** %v\n", "6")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	for _, node := range nodes {
		err = db.DelNode(node.ESAMPubKey)
		if err != nil {
			fmt.Printf("%v. Details: %v\n", "Failed to delete node", err)
			os.Exit(1)
		}
	}

	nodeFilter = data.Node{}

	fmt.Printf("*********************** %v\n", "7")

	nodes, err = db.ListNodes(&nodeFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to list nodes", err)
		os.Exit(1)
	}

	if len(nodes) != 0 {
		fmt.Printf("%v\n", "Number of records does not match expected")
		os.Exit(1)
	}

	os.Remove(dbFile)
}
