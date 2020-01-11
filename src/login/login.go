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

package login

import (
  "errors"
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
)

import (
  "esam/src/opts"
  "esam/src/data"
  "esam/src/keysconv"
  "esam/src/certs"
)

type Context struct {
  DirAddr string
  DirPort string
  TLSConfig tls.Config
  
  Key *rsa.PrivateKey
  ESAMPubKey data.ESAMPubKey
  VerifyKey data.ESAMPubKey
}

func MakeContext(esamKeyPath string, dirAddr string, dirPort string, tlsCACertPath string, verifyKeyPath string, esamKeyPassword string) (*Context, error) {
  var err error
  var loginContext *Context
  var tlsCAPool *x509.CertPool
  var verifyKey *rsa.PublicKey
  
  if dirAddr == "" {
    return nil, errors.New("Address to connect to Director was not defined")
  }
  
  if dirPort == "" {
    return nil, errors.New("Port to connect to Director was not defined")
  }
  
  loginContext = new(Context)
  
  loginContext.Key, err = keysconv.LoadKeyFromFile(esamKeyPath, esamKeyPassword)
  if err != nil {
    return nil, err
  }
  
  loginContext.ESAMPubKey, err = keysconv.PubKeyInRSAToPEM(&loginContext.Key.PublicKey)
  if err != nil {
    return nil, err
  }
  
  loginContext.DirAddr = dirAddr
  loginContext.DirPort = dirPort
  
  loginContext.TLSConfig.MinVersion = opts.TLSMinVersion
  
  if tlsCACertPath != "" {
    tlsCAPool, err = certs.LoadCertsBundle(tlsCACertPath)
    if err != nil {
      return nil, err
    }
    
    loginContext.TLSConfig.RootCAs = tlsCAPool
  }
  
  verifyKey, err = keysconv.LoadPubKeyFromFile(verifyKeyPath)
  if err != nil {
    return nil, err
  }
  
  loginContext.VerifyKey, err = keysconv.PubKeyInRSAToPEM(verifyKey)
  if err != nil {
    return nil, err
  }
  
  return loginContext, nil
}
