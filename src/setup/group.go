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

type groupAddOpts struct {
	Force     bool   `opt:"--force"`
	Gid       string `opt:"--gid"`
	NonUnique bool   `opt:"--non-unique"`
	Password  string `opt:"--password"`
	System    bool   `opt:"--system"`
	Root      string `opt:"--root"`
	Prefix    string `opt:"--prefix"`
}

type groupModOpts struct {
	Gid       string `opt:"--gid"`
	NewName   string `opt:"--new-name"`
	NonUnique bool   `opt:"--non-unique"`
	Password  string `opt:"--password"`
	Root      string `opt:"--root"`
	Prefix    string `opt:"--prefix"`
}

type groupDelOpts struct {
	Root   string `opt:"--root"`
	Prefix string `opt:"--prefix"`
	Force  bool   `opt:"--force"`
}

type GroupPresentOpts struct {
	Gid       string
	NonUnique bool
	Password  string
	System    bool
}

func groupadd(name string, cmdOpts *groupAddOpts) error {
	var err error
	var cmd *exec.Cmd
	var cmdArgs []string
	var cmdError bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "groupadd", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func groupmod(name string, cmdOpts *groupModOpts) error {
	var err error
	var cmd *exec.Cmd
	var cmdArgs []string
	var cmdError bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "groupmod", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func groupdel(name string, cmdOpts *groupDelOpts) error {
	var err error
	var cmd *exec.Cmd
	var cmdArgs []string
	var cmdError bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
	defer cancel()

	cmdArgs, err = buildArgs((*cmdOpts))
	if err != nil {
		return err
	}

	cmdArgs = append(cmdArgs, name)

	cmd = exec.CommandContext(ctx, "groupdel", cmdArgs...)
	cmd.Stderr = &cmdError

	err = cmd.Run()
	if err != nil {
		return errors.New(cmdError.String())
	}

	return nil
}

func GroupPresent(name string, groupOpts *GroupPresentOpts) error {
	var err error
	var castOk bool

	_, err = user.LookupGroup(name)
	_, castOk = err.(user.UnknownGroupError)

	if err != nil && !castOk {
		return err
	}

	groupModOpts := &groupModOpts{
		Gid:       groupOpts.Gid,
		NonUnique: groupOpts.NonUnique,
		Password:  groupOpts.Password,
	}

	groupAddOpts := &groupAddOpts{
		Gid:       groupOpts.Gid,
		NonUnique: groupOpts.NonUnique,
		Password:  groupOpts.Password,
		System:    groupOpts.System,
	}

	if err == nil {
		err = groupmod(name, groupModOpts)
		if err != nil {
			return err
		}
	} else {
		err = groupadd(name, groupAddOpts)
		if err != nil {
			return err
		}
	}

	return nil
}

func GroupAbsent(name string) error {
	var err error
	var castOk bool

	_, err = user.LookupGroup(name)
	_, castOk = err.(user.UnknownGroupError)

	if err != nil && !castOk {
		return err
	}

	if err != nil && castOk {
		return nil
	}

	err = groupdel(name, &groupDelOpts{})
	if err != nil {
		return err
	}

	return nil
}
