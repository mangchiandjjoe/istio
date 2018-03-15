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

// SecretServer is for implementing the communication from the node agent to the workload.
type SecretServer interface {
	// SetServiceIdentityPrivateKeyAndCert insert or update KeySertBundle
	SetIdentityKeyCertBundle(identity string, bundle util.KeyCertBundle) error
}

// NewSecretServer instantiates a SecretServer according to the configuration.
func NewSecretServer(cfg Config) (SecretServer, error) {
	switch cfg.Mode {
	case SecretFile:
		return &SecretFileServer{cfg}, nil
	case SecretDiscoveryServiceAPI:
		return &SDSServer{}, nil
	default:
		return nil, fmt.Errorf("mode: %d is not supported", cfg.Mode)
	}
}
