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
	"bytes"
	"context"
	"errors"
	"os/exec"
	"os/user"
)

import (
	"github.com/akramarenkov/esam/src/opts"
)

type userAddOpts struct {
	BaseDir      string   `opt:"--base-dir"`
	Comment      string   `opt:"--comment"`
	HomeDir      string   `opt:"--home-dir"`
	ExpireDate   string   `opt:"--expiredate"`
	Inactive     string   `opt:"--inactive"`
	Gid          string   `opt:"--gid"`
	Groups       []string `opt:"--groups"`
	Skel         string   `opt:"--skel"`
	NoLogInit    bool     `opt:"--no-log-init"`
	CreateHome   bool     `opt:"--create-home"`
	NoCreateHome bool     `opt:"--no-create-home"`
	NoUserGroup  bool     `opt:"--no-user-group"`
	NonUnique    bool     `opt:"--non-unique"`
	Password     string   `opt:"--password"`
	System       bool     `opt:"--system"`
	Root         string   `opt:"--root"`
	Prefix       string   `opt:"--prefix"`
	Shell        string   `opt:"--shell"`
	Uid          string   `opt:"--uid"`
	UserGroup    bool     `opt:"--user-group"`
	SELinuxUser  string   `opt:"--selinux-user"`
}

type userModOpts struct {
	Comment     string   `opt:"--comment"`
	Home        string   `opt:"--home"`
	ExpireDate  string   `opt:"--expiredate"`
	Inactive    string   `opt:"--inactive"`
	Gid         string   `opt:"--gid"`
	Groups      []string `opt:"--groups"`
	Append      bool     `opt:"--append"`
	Login       string   `opt:"--login"`
	Lock        bool     `opt:"--lock"`
	MoveHome    bool     `opt:"--move-home"`
	NonUnique   bool     `opt:"--non-unique"`
	Password    string   `opt:"--password"`
	Root        string   `opt:"--root"`
	Prefix      string   `opt:"--prefix"`
	Shell       string   `opt:"--shell"`
	Uid         string   `opt:"--uid"`
	Unlock      bool     `opt:"--unlock"`
	AddSubuids  string   `opt:"--add-subuids"`
	DelSubuids  string   `opt:"--del-subuids"`
	AddSubgids  string   `opt:"--add-subgids"`
	DelSubgids  string   `opt:"--del-subgids"`
	SELinuxUser string   `opt:"--selinux-user"`
}

type userDelOpts struct {
	Force       bool   `opt:"--force"`
	Remove      bool   `opt:"--remove"`
	Root        string `opt:"--root"`
	Prefix      string `opt:"--prefix"`
	SELinuxUser string `opt:"--selinux-user"`
}

/*
For add the option with empty value can set her corresponding field value to one space or one element with one space
*/

type UserPresentOpts struct {
	Comment    string
	ExpireDate string
	Inactive   string
	Gid        string
	Groups     []string
	Password   string
	Shell      string
	Uid        string
}

type UserAbsentOpts struct {
	Force  bool
	Remove bool
}

func useradd(name string, cmdOpts *userAddOpts) error {
	var (
		err      error
		cmd      *exec.Cmd
		cmdArgs  []string
		cmdError bytes.Buffer
	)

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "useradd", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func usermod(name string, cmdOpts *userModOpts) error {
	var (
		err      error
		cmd      *exec.Cmd
		cmdArgs  []string
		cmdError bytes.Buffer
	)

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "usermod", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func userdel(name string, cmdOpts *userDelOpts) error {
	var (
		err      error
		cmd      *exec.Cmd
		cmdArgs  []string
		cmdError bytes.Buffer
	)

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "userdel", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func UserPresent(name string, userOpts *UserPresentOpts) error {
	var (
		err    error
		castOk bool
	)

	_, err = user.Lookup(name)
	_, castOk = err.(user.UnknownUserError)

	if err != nil && !castOk {
		return err
	}

	userModOpts := &userModOpts{
		Comment:    userOpts.Comment,
		ExpireDate: userOpts.ExpireDate,
		Inactive:   userOpts.Inactive,
		Gid:        userOpts.Gid,
		Groups:     userOpts.Groups,
		Password:   userOpts.Password,
		Shell:      userOpts.Shell,
		Uid:        userOpts.Uid,
	}

	userAddOpts := &userAddOpts{
		Comment:    userOpts.Comment,
		ExpireDate: userOpts.ExpireDate,
		Inactive:   userOpts.Inactive,
		Gid:        userOpts.Gid,
		Groups:     userOpts.Groups,
		CreateHome: true,
		Password:   userOpts.Password,
		Shell:      userOpts.Shell,
		Uid:        userOpts.Uid,
	}

	if err == nil {
		err = usermod(name, userModOpts)
		if err != nil {
			return err
		}
	} else {
		err = useradd(name, userAddOpts)
		if err != nil {
			return err
		}
	}

	return nil
}

func UserAbsent(name string, userOpts *UserAbsentOpts) error {
	var (
		err    error
		castOk bool
	)

	_, err = user.Lookup(name)
	_, castOk = err.(user.UnknownUserError)

	if err != nil && !castOk {
		return err
	}

	if err != nil && castOk {
		return nil
	}

	userDeldOpts := &userDelOpts{
		Force:  userOpts.Force,
		Remove: userOpts.Remove,
	}

	err = userdel(name, userDeldOpts)
	if err != nil {
		return err
	}

	return nil
}
