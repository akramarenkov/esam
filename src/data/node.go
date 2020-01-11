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

package data

import (
  "errors"
  "strings"
  "crypto/rsa"
  "reflect"
)

import (
  "github.com/jinzhu/copier"
  "gopkg.in/yaml.v3"
)

import (
  "esam/src/types"
)

type Node struct {
  ESAMPubKey ESAMPubKey `yaml:"ESAM public key" json:"esam_pub_key" db:"esam_pub_key" sqltype:"VARBINARY(6144) NOT NULL PRIMARY KEY"`
  Name string `yaml:"Name" json:"name" db:"name" sqltype:"CHAR(63) NOT NULL UNIQUE"`
  SSHAddr string `yaml:"SSH address" json:"ssh_addr" db:"ssh_addr" sqltype:"CHAR(45)"`
  SSHPort string `yaml:"SSH port" json:"ssh_port" db:"ssh_port" sqltype:"CHAR(5)"`
}

type NodeSign struct {
  ESAMPubKeySign []byte `json:"esam_pub_key_sign" db:"esam_pub_key_sign" sqltype:"VARBINARY(4096)"`
  NameSign []byte `json:"name_sign" db:"name_sign" sqltype:"VARBINARY(4096)"`
  SSHAddrSign []byte `json:"ssh_addr_sign" db:"ssh_addr_sign" sqltype:"VARBINARY(4096)"`
  SSHPortSign []byte `json:"ssh_port_sign" db:"ssh_port_sign" sqltype:"VARBINARY(4096)"`
  SignSubject ESAMPubKey `json:"sign_subject" db:"sign_subject" sqltype:"VARBINARY(6144) NOT NULL"`
}

type NodeDB struct {
  Node
  NodeSign
}

/* Validated to data authenticity */
type NodeAuth struct {
  Node `yaml:",inline"`
  TrustedData string `yaml:"Trusted data" json:"trusted_data"`
}

func (node *Node) Copy() (*Node, error) {
  var err error
  var nodeOut *Node
  
  if node == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  nodeOut = new(Node)
  
  err = copier.Copy(nodeOut, node)
  if err != nil {
    return nil, err
  }
  
  return nodeOut, nil
}

func (node *NodeDB) Copy() (*NodeDB, error) {
  var err error
  var nodeOut *NodeDB
  
  if node == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  nodeOut = new(NodeDB)
  
  err = copier.Copy(nodeOut, node)
  if err != nil {
    return nil, err
  }
  
  return nodeOut, nil
}

func (node *NodeAuth) Copy() (*NodeAuth, error) {
  var err error
  var nodeOut *NodeAuth
  
  if node == nil {
    return nil, errors.New("Source struct pointer can't be nil")
  }
  
  nodeOut = new(NodeAuth)
  
  err = copier.Copy(nodeOut, node)
  if err != nil {
    return nil, err
  }
  
  return nodeOut, nil
}

func (node *Node) Normalize(toleratesEmptyFields bool) (error) {
  var err error
  var nodeTmp *Node
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  nodeTmp, err = node.Copy()
  if err != nil {
    return err
  }
  
  err = nodeTmp.ESAMPubKey.Normalize(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  nodeTmp.Name = strings.TrimSpace(nodeTmp.Name)
  nodeTmp.SSHAddr = strings.TrimSpace(nodeTmp.SSHAddr)
  nodeTmp.SSHPort = strings.TrimSpace(nodeTmp.SSHPort)
  
  (*node) = (*nodeTmp)
  
  return nil
}

func (node *NodeDB) Normalize() (error) {
  var err error
  var nodeTmp *NodeDB
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  nodeTmp, err = node.Copy()
  if err != nil {
    return err
  }
  
  nodeTmp.Node.Normalize(ToleratesEmptyFieldsNo)
  if err != nil {
    return err
  }
  
  if nodeTmp.NodeSign.SignSubject.Len() < 1 {
    nodeTmp.NodeSign.SignSubject.Template()
    if err != nil {
      return err
    }
  }
  
  (*node) = (*nodeTmp)
  
  return nil
}

func (node *NodeAuth) Normalize(toleratesEmptyFields bool) (error) {
  var err error
  var nodeTmp *NodeAuth
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  nodeTmp, err = node.Copy()
  if err != nil {
    return err
  }
  
  nodeTmp.Node.Normalize(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  nodeTmp.TrustedData = types.NormalizeBoolString(nodeTmp.TrustedData)
  
  (*node) = (*nodeTmp)
  
  return nil
}

func (node *Node) Test(toleratesEmptyFields bool) (error) {
  var err error
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = node.ESAMPubKey.Test(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  if node.Name == "" && !toleratesEmptyFields {
    return errors.New("Node name cannot be empty")
  }
  
  return nil
}

func (node *NodeDB) Test() (error) {
  var err error
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = node.Node.Test(ToleratesEmptyFieldsNo)
  if err != nil {
    return err
  }
  
  if node.NodeSign.SignSubject.Len() < 1 {
    return errors.New("Sign subject can't be empty")
  }
  
  return nil
}

func (node *NodeAuth) Test(toleratesEmptyFields bool) (error) {
  var err error
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = node.Node.Test(toleratesEmptyFields)
  if err != nil {
    return err
  }
  
  err = types.TestBoolString(node.TrustedData, toleratesEmptyFields)
  
  return nil
}

func (node *Node) Equal(nodeTwo *Node) (bool) {
  if node == nil {
    return false
  }
  
  if nodeTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(node, nodeTwo)
}

func (node *NodeDB) Equal(nodeTwo *NodeDB) (bool) {
  if node == nil {
    return false
  }
  
  if nodeTwo == nil {
    return false
  }
  
  return reflect.DeepEqual(node, nodeTwo)
}

func (node *NodeDB) Sign(key *rsa.PrivateKey) (error) {
  var err error
  var nodeTmp *NodeDB
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if key == nil {
    return errors.New("Key pointer can't be nil")
  }
  
  nodeTmp, err = node.Copy()
  if err != nil {
    return err
  }
  
  err = signStruct(&nodeTmp.Node, &nodeTmp.NodeSign, key, nil)
  if err != nil {
    return err
  }
  
  (*node) = (*nodeTmp)
  
  return nil
}

func (node *NodeDB) Verify() (error) {
  var err error
  
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  err = verifyStruct(&node.Node, &node.NodeSign, nil)
  if err != nil {
    return err
  }
  
  return nil
}

func (node Node) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(node)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (node *Node) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), node)
  if err != nil {
    return err
  }
  
  return nil
}

func (node NodeAuth) String() (string) {
  var err error
  var out []byte
  
  out, err = yaml.Marshal(node)
  if err != nil {
    return ""
  }
  
  return string(out[:])
}

func (node *NodeAuth) FromString(data string) (error) {
  var err error
  
  err = yaml.Unmarshal([]byte(data), node)
  if err != nil {
    return err
  }
  
  return nil
}

func (node *Node) Template() (error) {
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  node.ESAMPubKey.Template()
  node.SSHPort = "22"
  
  return nil
}

func (node *NodeDB) Template() (error) {
  if node == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  node.Node.Template()
  node.NodeSign.SignSubject.Template()
  
  return nil
}
