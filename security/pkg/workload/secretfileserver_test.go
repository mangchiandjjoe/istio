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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	_ "os"

	"fmt"

	"istio.io/istio/security/pkg/pki/util"
	fileUtil "istio.io/istio/security/pkg/util"
)

func readFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func TestSecretFileServer(t *testing.T) {
	tmpdir, _ := ioutil.TempDir("", "file")
	defer func() {
		// os.RemoveAll(tmpdir)
	}()

	server := SecretFileServer{
		cfg: Config{
			FileUtil:           fileUtil.FileUtilImpl{},
			ServiceIdentityDir: tmpdir,
		},
	}

	// prepare the KeyCertBundle
	bundle, err := util.NewVerifiedKeyCertBundleFromFile(
		"../../samples/plugin_ca_certs/ca-cert.pem", "../../samples/plugin_ca_certs/ca-key.pem",
		"../../samples/plugin_ca_certs/cert-chain.pem", "../../samples/plugin_ca_certs/root-cert.pem")
	if err != nil {
		t.Fatalf("failed to generate KeyCertBuldleFromPem")
	}

	// test SetIdentityKeyCertBundle
	if bundleErr := server.SetIdentityKeyCertBundle("test", bundle); bundleErr != nil {
		t.Errorf("%v", bundleErr)
	}

	// validate file contents
	cert, err := readFile(fmt.Sprintf("%s/%s/cert.pem", tmpdir, "test"))
	if err != nil {
		t.Errorf("failed to read certificate: %v", err)
	}

	key, err := readFile(fmt.Sprintf("%s/%s/key.pem", tmpdir, "test"))
	if err != nil {
		t.Errorf("failed to read private key: %v", err)
	}

	root, err := readFile(fmt.Sprintf("%s/%s/root.pem", tmpdir, "test"))
	if err != nil {
		t.Errorf("failed to read root certificate: %v", err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(root))
	if !ok {
		panic("failed to parse root certificate")
	}

	// Verify certificate and private key
	if _, err = tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
		t.Fatalf("failed to verify private key and certificate: %v", err)
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "ca.istio.io",
		Roots:   roots,
	}

	if _, err := certificate.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
}
