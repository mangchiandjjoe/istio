// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workload

import (
	"fmt"

	"istio.io/istio/security/pkg/pki/util"
)

const (
	keyFilePermission  = 0600
	certFilePermission = 0644
)

// SecretFileServer is an implementation of SecretServer that writes the key/cert into file system.
type SecretFileServer struct {
	cfg Config
}

// SetIdentityKeyCertBundle sets the service identity private key into the file system.
func (sf *SecretFileServer) SetIdentityKeyCertBundle(identity string, bundle util.KeyCertBundle) error {
	cert, key, chain, root := bundle.GetAllPem()

	if err := sf.cfg.FileUtil.Write(fmt.Sprintf("%s/%s/key.pem", sf.cfg.ServiceIdentityDir, identity),
		key, keyFilePermission); err != nil {
		return fmt.Errorf("unable to store private key: %v", err)
	}

	if err := sf.cfg.FileUtil.Write(fmt.Sprintf("%s/%s/cert.pem", sf.cfg.ServiceIdentityDir, identity),
		cert, certFilePermission); err != nil {
		return fmt.Errorf("unable to store certificate: %v", err)
	}

	if err := sf.cfg.FileUtil.Write(fmt.Sprintf("%s/%s/chain.pem", sf.cfg.ServiceIdentityDir, identity),
		chain, certFilePermission); err != nil {
		return fmt.Errorf("unable to store certificate chain: %v", err)
	}

	if err := sf.cfg.FileUtil.Write(fmt.Sprintf("%s/%s/root.pem", sf.cfg.ServiceIdentityDir, identity),
		root, certFilePermission); err != nil {
		return fmt.Errorf("unable to store root certificate: %v", err)
	}

	return nil
}
