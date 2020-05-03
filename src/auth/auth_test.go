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

package auth

import (
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
)

import (
	"esam/src/data"
	"esam/src/db"
	"esam/src/keysconv"
	"esam/src/netapi"
)

import (
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbFile = "test.db"
)

func Test(t *testing.T) {
	var err error

	var verifyKeyPrivatePEM []byte
	var verifyKeyPrivate *rsa.PrivateKey
	var verifyKeyESAMPubKey data.ESAMPubKey

	var OwnerOne data.UserDB
	var OwnerOneFilter data.User
	var OwnerOnePrivateKeyPEM []byte
	var OwnerOnePrivateKey *rsa.PrivateKey
	var OwnerOneESAMPubKey data.ESAMPubKey

	var OwnerTwo data.UserDB
	//var OwnerTwoFilter data.User
	var OwnerTwoPrivateKeyPEM []byte
	var OwnerTwoPrivateKey *rsa.PrivateKey
	var OwnerTwoESAMPubKey data.ESAMPubKey

	var SecAdminOne data.UserDB
	var SecAdminOnePrivateKeyPEM []byte
	var SecAdminOnePrivateKey *rsa.PrivateKey
	var SecAdminOneESAMPubKey data.ESAMPubKey

	var SecAdminTwo data.UserDB
	var SecAdminTwoPrivateKeyPEM []byte
	var SecAdminTwoPrivateKey *rsa.PrivateKey
	var SecAdminTwoESAMPubKey data.ESAMPubKey

	var EngineerOne data.UserDB
	var EngineerTwo data.UserDB

	var db db.Desc

	var udsAuthContext *Context
	var ownerOneAuthContext *Context
	var ownerTwoAuthContext *Context
	var secAdminOneAuthContext *Context
	var secAdminTwoAuthContext *Context
	var engineerOneAuthContext *Context
	var engineerTwoAuthContext *Context

	var userFilter data.User
	var usersList []data.UserDB

	var NodeOne data.NodeDB
	var NodeTwo data.NodeDB

	var checkAccessRightsResult bool
	var dataTrusted bool

	verifyKeyPrivatePEM = []byte(`-----BEGIN PRIVATE KEY-----
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
In2I+5OpmLcNsVFVqkwcD4GF8ufRqg==
-----END PRIVATE KEY-----`)

	verifyKeyPrivate, err = keysconv.KeyInPEMToRSA(verifyKeyPrivatePEM[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert verify private key from PEM", err)
		os.Exit(1)
	}

	verifyKeyESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&verifyKeyPrivate.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert public key to PEM", err)
		os.Exit(1)
	}

	OwnerOne.Template()
	OwnerTwo.Template()
	SecAdminOne.Template()
	SecAdminTwo.Template()
	EngineerOne.Template()
	EngineerTwo.Template()

	OwnerOnePrivateKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
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
2fpxajCzvK9ryUwWx9W0Wm8jl21Lmw==
-----END PRIVATE KEY-----`)

	OwnerOnePrivateKey, err = keysconv.KeyInPEMToRSA(OwnerOnePrivateKeyPEM[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert OwnerOne private key from PEM", err)
		os.Exit(1)
	}

	OwnerOneESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&OwnerOnePrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert OwnerOne public key to PEM", err)
		os.Exit(1)
	}

	OwnerOne = data.UserDB{
		User: data.User{
			ESAMPubKey:        OwnerOneESAMPubKey,
			Name:              "OwnerOne",
			Role:              data.UserRoleOwner,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key OwnerOne",
			PasswordHash:      "password hash OwnerOne",
			ElevatePrivileges: true,
		},
		UserSign: OwnerOne.UserSign,
	}

	OwnerTwoPrivateKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
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
dsbtUzU0g4G5a/e82/Kzkh53ajcY7A==
-----END PRIVATE KEY-----`)

	OwnerTwoPrivateKey, err = keysconv.KeyInPEMToRSA(OwnerTwoPrivateKeyPEM[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert OwnerTwo private key from PEM", err)
		os.Exit(1)
	}

	OwnerTwoESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&OwnerTwoPrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert OwnerTwo public key to PEM", err)
		os.Exit(1)
	}

	OwnerTwo = data.UserDB{
		User: data.User{
			ESAMPubKey:        OwnerTwoESAMPubKey,
			Name:              "OwnerTwo",
			Role:              data.UserRoleOwner,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key OwnerTwo",
			PasswordHash:      "password hash OwnerTwo",
			ElevatePrivileges: true,
		},
		UserSign: OwnerTwo.UserSign,
	}

	SecAdminOnePrivateKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
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
nucbcHW8j0PGtltMz4vgv5rbDiYxt9oI
-----END PRIVATE KEY-----`)

	SecAdminOnePrivateKey, err = keysconv.KeyInPEMToRSA(SecAdminOnePrivateKeyPEM[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert SecAdminOne private key from PEM", err)
		os.Exit(1)
	}

	SecAdminOneESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&SecAdminOnePrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert SecAdminOne public key to PEM", err)
		os.Exit(1)
	}

	SecAdminOne = data.UserDB{
		User: data.User{
			ESAMPubKey:        SecAdminOneESAMPubKey,
			Name:              "SecAdminOne",
			Role:              data.UserRoleSecAdmin,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key SecAdminOne",
			PasswordHash:      "password hash SecAdminOne",
			ElevatePrivileges: true,
		},
		UserSign: SecAdminOne.UserSign,
	}

	SecAdminTwoPrivateKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
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
2UoQemzakBMQ/GI/Ym259HrAxJd+Wqk=
-----END PRIVATE KEY-----`)

	SecAdminTwoPrivateKey, err = keysconv.KeyInPEMToRSA(SecAdminTwoPrivateKeyPEM[:])
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert SecAdminTwo private key from PEM", err)
		os.Exit(1)
	}

	SecAdminTwoESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&SecAdminTwoPrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to convert SecAdminTwo public key to PEM", err)
		os.Exit(1)
	}

	SecAdminTwo = data.UserDB{
		User: data.User{
			ESAMPubKey:        SecAdminTwoESAMPubKey,
			Name:              "SecAdminTwo",
			Role:              data.UserRoleSecAdmin,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key SecAdminTwo",
			PasswordHash:      "password hash SecAdminTwo",
			ElevatePrivileges: true,
		},
		UserSign: SecAdminTwo.UserSign,
	}

	EngineerOne = data.UserDB{
		User: data.User{
			ESAMPubKey: data.ESAMPubKey(`-----BEGIN PUBLIC KEY-----
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
			Name:              "EngineerOne",
			Role:              data.UserRoleEngineer,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key EngineerOne",
			PasswordHash:      "password hash EngineerOne",
			ElevatePrivileges: true,
		},
		UserSign: EngineerOne.UserSign,
	}

	EngineerTwo = data.UserDB{
		User: data.User{
			ESAMPubKey: data.ESAMPubKey(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvDdChyd2HCs3VeSFThjk
5MDL2+0GVYv+xmx1MY3tv7yQsFlqUbDrdtFf9HR3w7aXjIumwu/AXcE3Kx+uksLw
qg3tOBifkolAp8dah92QusOumW5ZYLs37zq6Nq9YdKg8k4RFOSodmMlBbudE1OF8
llcZyaIVwDMJ7l8Q6ra4anmDCqBvycs96+GrrBH9qu+aOxfyM3YtmJ/qa1sDeDmt
ILP7icrSGozv0k+HNyrJ8TzxQEijikIJaDemHV7DfgFfaKm5PjmNqmPv8n6qns1f
IjTKq4v4NwhG6AA9uNfkVbI3enPrXl/qxWzs/eBcUus8/u0LFGZHzNzSrxZ8YKMo
bySIWTFu3lRNpKu5oeV7onymjbZlfGsj6XVxQ4Iyr1s8hx6Tsqpfw97XJmM4rJf0
8G+XMPUIhssVcBnYmZzhrx2r79YRmqD8OTe8esmRXgCqvnGcbMubh7+TS4EfBUQd
ltLwVVkr9eEijyO9VBIbyThgbmSulwba/XicfdSPSh6MQFrQj+HwG1tjODQhlk6H
OiY4Dh+17W5zzysAWQhYx5JyYgfYNYaA0iiihSjKxM7k8kElY6SOCoq15vsWAtth
r6v4F05vdUYMTkBAPzJ77buFDlrgdfIMYDZptND1t3q8ZFPt2L31pJ/OVZA3Near
54FKPNSiC226uO/yeYE2tMUCAwEAAQ==
-----END PUBLIC KEY-----`),
			Name:              "EngineerTwo",
			Role:              data.UserRoleEngineer,
			State:             data.UserStateEnabled,
			SSHPubKey:         "SSH public key EngineerTwo",
			PasswordHash:      "password hash EngineerTwo",
			ElevatePrivileges: false,
		},
		UserSign: EngineerTwo.UserSign,
	}

	NodeOne = data.NodeDB{
		Node: data.Node{
			ESAMPubKey: data.ESAMPubKey(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3JMAjkJFrJgx8rx6b1Jv
qcFSH6NYA+AH2QnR/lbBTa7o19XKoY/Qxn9srgpbawdldaJ8W71kVD9W2Cbrxd/O
L6k1xiLOGxgponODsWiBA2E1BG8vPNuErxfB/ggeoj5hlqSyhSxYMw5Dm5WCsiB8
4jpxvJ+yRRdfTb1XUkIpl9ZDgOANftvYLhp0dyqxfr9E875aGONnC3fhj7V54FaZ
cGnBhsuZvW0K1ophXBktEGgbK8FcJr/DQdKla54tr0We+jl6eLEZ22cLSx/SsI28
7YyNvOPIZJIFF09jQ3LaNnXRRZoZNB85kf7stJMDkN5Eew2F7zoJR7apEPudjKZz
6tffkSbvk1jdGOIdT2hfF8DKlpwT/Cyk2mrQiedAvFk4gHjJK6JLppsIevbUmyE6
jkKRr1+TVDZVo8DulF1PbDwecAVJa9+fmwgdk3g1LAfJVUdgRCn63Mgl8O1Smz8M
F7FQxUJh1VVU8sV3aHHKUn8wtIuMwA2I67jvkzFn4+cyrq857yxrnUwazTUTHCMM
mJO+/48jd+CbWZlqiBdsv82sWVxmgf4DP56YL6WrTynB5XPYGnxhX/Rf7Wn3pXk0
CzaAEm/7qqlPGW690qRI0VkLaXRw3QzMGsQDK4FBp1UH7ila4Ai1liM/ri1hEC5B
3W43bkJE9YSuuFfoJ0U6lesCAwEAAQ==
-----END PUBLIC KEY-----`),
			Name: "NodeOne",
		},
	}

	NodeTwo = data.NodeDB{
		Node: data.Node{
			ESAMPubKey: data.ESAMPubKey(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5BL1uiq/r3FWEdLXsTn4
L7dV1NeqZbp+U4234y6mnpCtxBb81HnU/Xg+mMz7/k8dwdjPuUXTyoSqq5c8Kkq3
kdijrEk/11WROKW6H3o6t54dzmX6DKYHRHNvuFHpMCP2IGE4BqXZcVhp8o8QYkU7
vUVkucSm6i+HmI3Q6dno1Z6J9VfuuABW3QBX4NLxYfJwfeQcylNOvweHIG6XEsG8
XNo9NTFWtap8LDckgTQZuKw/Myzi0QBvfcdghpBZgBqYceFAgc3IIBdfzDljzKZY
kHO+EyRt5idjSm0V4clD16W5xDvOqqxJC0kRlE0GRnmqKRc3cykM8Vbz8vW1sv2q
8JtkHdW7iz+9fdvrPDy0iJCYGzOkwZt0NHkfynVdDS61Svu8LTHwknJtW7m/07ag
NlD9BzjgTdSHduHJQd3l7ed7um2LlYgdB6ll4YcWm4NFskmxK0fUbaYyXEyTdAPg
o19t/tYAmJIwSq9a3U+Nhgx7+cBlUcoeXwzyChi95AcPyxe7f1rSak6Ap7B70eWZ
TJTqD9ZFFvgb/4xw6KbplIJlpStueMSzcCdbMtbZRcF2fZCZZs1xFDii5ASX43Mq
4vpOVEyPR0DBuVyXdb87dz1HyMyWWu0ZM1JutJqxg4diocYEdvZQQcRx9VjSSQmq
OkKdW+i3LJ9iL+6rj86PzCcCAwEAAQ==
-----END PUBLIC KEY-----`),
			Name: "NodeTwo",
		},
	}

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

	/* Add owners over UDS */

	udsAuthContext = &Context{SubjectType: SubjectUDS, SubjectData: nil}

	checkAccessRightsResult, err = CheckSubjectAccessRights(udsAuthContext, OwnerOne, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, udsAuthContext.SubjectType, OwnerOne.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&OwnerOne)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(udsAuthContext, OwnerTwo, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, udsAuthContext.SubjectType, OwnerTwo.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&OwnerTwo)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	/* Owners authentication */

	ownerOneAuthContext, err = IdentifySubject(&OwnerOne.ESAMPubKey, &db)
	if err != nil || ownerOneAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", OwnerOne.Name, err)
		os.Exit(1)
	}

	ownerTwoAuthContext, err = IdentifySubject(&OwnerTwo.ESAMPubKey, &db)
	if err != nil || ownerTwoAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", OwnerTwo.Name, err)
		os.Exit(1)
	}

	/* Re-sign OwnerOne data by verify key (private) and update his data in DB */

	err = OwnerOne.Sign(verifyKeyPrivate, nil)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign OwnerOne", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, OwnerOne, OwnerOne, netapi.ReqTypeUpdateUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, OwnerOne.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	OwnerOneFilter.ESAMPubKey = OwnerOne.ESAMPubKey
	err = db.UpdateUser(&OwnerOneFilter, &OwnerOne)
	if err != nil {
		fmt.Printf("Failed to update '%v'. Details: %v\n", OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, OwnerOne, OwnerOne, netapi.ReqTypeChangePassword)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, OwnerOne.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	/* Owner should not be able to update the data of another owner, including password or delete another owner*/

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, OwnerOne, OwnerTwo, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, OwnerOne.Name, OwnerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, OwnerOne, OwnerTwo, netapi.ReqTypeChangePassword)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, OwnerOne.Name, OwnerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, OwnerOne, OwnerTwo, netapi.ReqTypeDelUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, OwnerOne.Name, OwnerTwo.Name, err)
		os.Exit(1)
	}

	/* Owner should be able to add, update and delete an security administrator and engineer of course */

	err = SecAdminOne.Sign(OwnerOnePrivateKey, nil)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign SecAdminOne", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, SecAdminOne, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, OwnerOne.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&SecAdminOne)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	err = SecAdminTwo.Sign(OwnerTwoPrivateKey, nil)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign SecAdminTwo", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, SecAdminTwo, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, OwnerOne.Name, SecAdminTwo.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&SecAdminTwo)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, SecAdminTwo, SecAdminTwo, netapi.ReqTypeUpdateUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, OwnerOne.Name, SecAdminTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, nil, SecAdminTwo, netapi.ReqTypeDelUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, OwnerOne.Name, SecAdminTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, EngineerTwo, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, OwnerOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, EngineerTwo, EngineerTwo, netapi.ReqTypeUpdateUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, OwnerOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, nil, EngineerTwo, netapi.ReqTypeDelUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, OwnerOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	/* Security administrators authentication */

	secAdminOneAuthContext, err = IdentifySubject(&SecAdminOne.ESAMPubKey, &db)
	if err != nil || ownerOneAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", SecAdminOne.Name, err)
		os.Exit(1)
	}

	secAdminTwoAuthContext, err = IdentifySubject(&SecAdminTwo.ESAMPubKey, &db)
	if err != nil || ownerTwoAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", SecAdminTwo.Name, err)
		os.Exit(1)
	}

	/*
	  Security administrators should be able to:
	    - add, update and delete an engineer
	    - change own password (but not password hash)
	*/

	err = EngineerOne.Sign(SecAdminOnePrivateKey, nil)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign SecAdminOne", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, EngineerOne, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, SecAdminOne.Name, EngineerOne.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&EngineerOne)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	err = EngineerTwo.Sign(SecAdminOnePrivateKey, nil)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign SecAdminOne", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, EngineerTwo, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, SecAdminOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	err = db.AddUser(&EngineerTwo)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddUser", err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, SecAdminOne, SecAdminOne, netapi.ReqTypeChangePassword)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, SecAdminOne.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, EngineerTwo, nil, netapi.ReqTypeAddUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, EngineerTwo, EngineerTwo, netapi.ReqTypeUpdateUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, EngineerTwo, netapi.ReqTypeDelUser)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, SecAdminOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	/*
	  Security administrators should not be able to:
	    - add, update and delete owners
	    - add, update and delete security administrators
	    - increase role of engineer and security administrators
	    - reduce role of owner and security administrators
	    - increase or reduce own role
	    - update own data including password hash
	*/

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, OwnerOne, nil, netapi.ReqTypeAddUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, SecAdminTwo.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminOne, nil, netapi.ReqTypeAddUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, SecAdminTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, OwnerOne, OwnerOne, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminOne, SecAdminOne, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, OwnerOne, netapi.ReqTypeDelUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, SecAdminTwo.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, SecAdminOne, netapi.ReqTypeDelUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, SecAdminTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	OwnerOneAsSecAdmin := OwnerOne
	OwnerOneAsSecAdmin.Role = data.UserRoleSecAdmin
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, OwnerOne, OwnerOneAsSecAdmin, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, OwnerOneAsSecAdmin.Name, err)
		os.Exit(1)
	}

	OwnerOneAsEngineer := OwnerOne
	OwnerOneAsEngineer.Role = data.UserRoleEngineer
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, OwnerOne, OwnerOneAsEngineer, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, OwnerOneAsEngineer.Name, err)
		os.Exit(1)
	}

	SecAdminOneAsEngineer := SecAdminOne
	SecAdminOneAsEngineer.Role = data.UserRoleEngineer
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminOne, SecAdminOneAsEngineer, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminOneAsEngineer.Name, err)
		os.Exit(1)
	}

	SecAdminOneAsOwner := SecAdminOne
	SecAdminOneAsOwner.Role = data.UserRoleOwner
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminOne, SecAdminOneAsOwner, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminOneAsOwner.Name, err)
		os.Exit(1)
	}

	EngineerOneAsSecAdmin := EngineerOne
	EngineerOneAsSecAdmin.Role = data.UserRoleSecAdmin
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, EngineerOne, EngineerOneAsSecAdmin, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, EngineerOneAsSecAdmin.Name, err)
		os.Exit(1)
	}

	EngineerOneAsOwner := EngineerOne
	EngineerOneAsOwner.Role = data.UserRoleOwner
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, EngineerOne, EngineerOneAsOwner, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, EngineerOneAsOwner.Name, err)
		os.Exit(1)
	}

	SecAdminTwoAsEngineer := SecAdminTwo
	SecAdminTwoAsEngineer.Role = data.UserRoleEngineer
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminTwo, SecAdminTwoAsEngineer, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminTwoAsEngineer.Name, err)
		os.Exit(1)
	}

	SecAdminTwoAsOwner := SecAdminTwo
	SecAdminTwoAsOwner.Role = data.UserRoleOwner
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminTwo, SecAdminTwoAsOwner, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminTwoAsOwner.Name, err)
		os.Exit(1)
	}

	SecAdminTwoWithOtherPasswordHash := SecAdminTwo
	SecAdminTwoWithOtherPasswordHash.PasswordHash = "Other password hash SecAdminTwo"
	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminTwo, SecAdminTwoWithOtherPasswordHash, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, SecAdminTwo.Name, SecAdminTwoWithOtherPasswordHash.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminTwoAuthContext, SecAdminOne, SecAdminOne, netapi.ReqTypeChangePassword)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, SecAdminTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	/* Engineers authentication */

	engineerOneAuthContext, err = IdentifySubject(&EngineerOne.ESAMPubKey, &db)
	if err != nil || ownerOneAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", EngineerOne.Name, err)
		os.Exit(1)
	}

	engineerTwoAuthContext, err = IdentifySubject(&EngineerTwo.ESAMPubKey, &db)
	if err != nil || ownerTwoAuthContext == nil {
		fmt.Printf("Failed to identify subject for '%v'. Details: %v\n", EngineerTwo.Name, err)
		os.Exit(1)
	}

	/* Engineers may only change own password (but not password hash) */

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, OwnerOne, nil, netapi.ReqTypeAddUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, EngineerOne.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, OwnerOne, OwnerOne, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, EngineerOne.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, nil, OwnerOne, netapi.ReqTypeDelUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, EngineerOne.Name, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerTwoAuthContext, SecAdminOne, nil, netapi.ReqTypeAddUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeAddUser, EngineerTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerTwoAuthContext, SecAdminOne, SecAdminOne, netapi.ReqTypeUpdateUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeUpdateUser, EngineerTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerTwoAuthContext, nil, SecAdminOne, netapi.ReqTypeDelUser)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeDelUser, EngineerTwo.Name, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, EngineerOne, EngineerOne, netapi.ReqTypeChangePassword)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, EngineerOne.Name, EngineerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, EngineerTwo, EngineerTwo, netapi.ReqTypeChangePassword)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v' for '%v'. Details: %v\n", netapi.ReqTypeChangePassword, EngineerOne.Name, EngineerTwo.Name, err)
		os.Exit(1)
	}

	userFilter = data.User{}
	usersList, err = db.ListUsers(&userFilter)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.ListUsers", err)
	}

	dataTrusted, err = CheckUserDataAuthenticity(&OwnerOne, usersList, &verifyKeyESAMPubKey)
	if err != nil || dataTrusted == false {
		fmt.Printf("Unexpected data authenticity for %v\n", OwnerOne.Name)
	}

	/* OwnerTwo data not pass authenticity checks because his data not signed by verify key */

	dataTrusted, err = CheckUserDataAuthenticity(&OwnerTwo, usersList, &verifyKeyESAMPubKey)
	if err == nil || dataTrusted == true {
		fmt.Printf("Unexpected data authenticity for %v\n", OwnerTwo.Name)
	}

	dataTrusted, err = CheckUserDataAuthenticity(&SecAdminOne, usersList, &verifyKeyESAMPubKey)
	if err != nil || dataTrusted == false {
		fmt.Printf("Unexpected data authenticity for %v\n", SecAdminOne.Name)
	}

	/* SecAdminTwo data not pass authenticity checks because his data signed by OwnerTwo */

	dataTrusted, err = CheckUserDataAuthenticity(&SecAdminTwo, usersList, &verifyKeyESAMPubKey)
	if err == nil || dataTrusted == true {
		fmt.Printf("Unexpected data authenticity for %v\n", SecAdminTwo.Name)
	}

	dataTrusted, err = CheckUserDataAuthenticity(&EngineerOne, usersList, &verifyKeyESAMPubKey)
	if err != nil || dataTrusted == false {
		fmt.Printf("Unexpected data authenticity for %v\n", EngineerOne.Name)
	}

	dataTrusted, err = CheckUserDataAuthenticity(&EngineerTwo, usersList, &verifyKeyESAMPubKey)
	if err != nil || dataTrusted == false {
		fmt.Printf("Unexpected data authenticity for %v\n", EngineerTwo.Name)
	}

	/* Node can be added, updated and deleted only by Owners and Security Administrators */

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, nil, nil, netapi.ReqTypeAddNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeAddNode, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, nil, nil, netapi.ReqTypeUpdateNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeUpdateNode, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(ownerOneAuthContext, nil, nil, netapi.ReqTypeDelNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeDelNode, OwnerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, nil, netapi.ReqTypeAddNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeAddNode, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, nil, netapi.ReqTypeUpdateNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeUpdateNode, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(secAdminOneAuthContext, nil, nil, netapi.ReqTypeDelNode)
	if err != nil || checkAccessRightsResult == false {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeDelNode, SecAdminOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, nil, nil, netapi.ReqTypeAddNode)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeAddNode, EngineerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, nil, nil, netapi.ReqTypeUpdateNode)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeUpdateNode, EngineerOne.Name, err)
		os.Exit(1)
	}

	checkAccessRightsResult, err = CheckSubjectAccessRights(engineerOneAuthContext, nil, nil, netapi.ReqTypeDelNode)
	if err == nil && checkAccessRightsResult == true {
		fmt.Printf("Failed to check access rights to '%v' by '%v'. Details: %v\n", netapi.ReqTypeDelNode, EngineerOne.Name, err)
		os.Exit(1)
	}

	err = NodeOne.Sign(SecAdminOnePrivateKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign node one by SecAdminOne", err)
		os.Exit(1)
	}

	err = NodeTwo.Sign(SecAdminTwoPrivateKey)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to sign node two by SecAdminTwo", err)
		os.Exit(1)
	}

	err = db.AddNode(&NodeOne)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddNode", err)
		os.Exit(1)
	}

	err = db.AddNode(&NodeTwo)
	if err != nil {
		fmt.Printf("%v. Details: %v\n", "Failed to db.AddNode", err)
		os.Exit(1)
	}

	dataTrusted, err = CheckNodeDataAuthenticity(&NodeOne, usersList, &verifyKeyESAMPubKey)
	if err != nil || dataTrusted == false {
		fmt.Printf("Unexpected data authenticity for %v\n", NodeOne.Name)
	}

	/* NodeTwo data must not pass authenticity checks because data of SecAdminTwo not pass authenticity checks */

	dataTrusted, err = CheckNodeDataAuthenticity(&NodeTwo, usersList, &verifyKeyESAMPubKey)
	if err == nil && dataTrusted == true {
		fmt.Printf("Unexpected data authenticity for %v\n", NodeTwo.Name)
	}

	os.Remove(dbFile)
}
