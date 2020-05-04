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

package certs

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func LoadCertsBundle(bundlePath string) (*x509.CertPool, error) {
	var (
		err           error
		certsPool     *x509.CertPool
		bundleContent []byte
		pemBlock      *pem.Block
		certs         []*x509.Certificate
	)

	certsPool = x509.NewCertPool()

	bundleContent, err = ioutil.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}

	pemBlock, _ = pem.Decode(bundleContent)
	if pemBlock == nil {
		return nil, err
	}

	certs, err = x509.ParseCertificates(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		certsPool.AddCert(cert)
	}

	return certsPool, nil
}
