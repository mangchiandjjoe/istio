// Copyright 2018 Istio Authors
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
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"istio.io/istio/security/pkg/pki/util"
)

var (
	rootCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIID7TCCAtWgAwIBAgIJAOIRDhOcxsx6MA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl
MQ4wDAYDVQQKDAVJc3RpbzENMAsGA1UECwwEVGVzdDEQMA4GA1UEAwwHUm9vdCBD
QTEiMCAGCSqGSIb3DQEJARYTdGVzdHJvb3RjYUBpc3Rpby5pbzAgFw0xODAxMjQx
OTE1NTFaGA8yMTE3MTIzMTE5MTU1MVowgYsxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRIwEAYDVQQHDAlTdW5ueXZhbGUxDjAMBgNVBAoMBUlzdGlv
MQ0wCwYDVQQLDARUZXN0MRAwDgYDVQQDDAdSb290IENBMSIwIAYJKoZIhvcNAQkB
FhN0ZXN0cm9vdGNhQGlzdGlvLmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA38uEfAatzQYqbaLou1nxJ348VyNzumYMmDDt5pbLYRrCo2pS3ki1ZVDN
8yxIENJFkpKw9UctTGdbNGuGCiSDP7uqF6BiVn+XKAU/3pnPFBbTd0S33NqbDEQu
IYraHSl/tSk5rARbC1DrQRdZ6nYD2KrapC4g0XbjY6Pu5l4y7KnFwSunnp9uqpZw
uERv/BgumJ5QlSeSeCmhnDhLxooG8w5tC2yVr1yDpsOHGimP/mc8Cds4V0zfIhQv
YzfIHphhE9DKjmnjBYLOdj4aycv44jHnOGc+wvA1Jqsl60t3wgms+zJTiWwABLdw
zgMAa7yxLyoV0+PiVQud6k+8ZoIFcwIDAQABo1AwTjAdBgNVHQ4EFgQUOUYGtUyh
euxO4lGe4Op1y8NVoagwHwYDVR0jBBgwFoAUOUYGtUyheuxO4lGe4Op1y8NVoagw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEANXLyfAs7J9rmBamGJvPZ
ltx390WxzzLFQsBRAaH6rgeipBq3dR9qEjAwb6BTF+ROmtQzX+fjstCRrJxCto9W
tC8KvXTdRfIjfCCZjhtIOBKqRxE4KJV/RBfv9xD5lyjtCPCQl3Ia6MSf42N+abAK
WCdU6KCojA8WB9YhSCzza3aQbPTzd26OC/JblJpVgtus5f8ILzCsz+pbMimgTkhy
AuhYRppJaQ24APijsEC9+GIaVKPg5IwWroiPoj+QXNpshuvqVQQXvGaRiq4zoSnx
xAJz+w8tjrDWcf826VN14IL+/Cmqlg/rIfB5CHdwVIfWwpuGB66q/UiPegZMNs8a
3g==
-----END CERTIFICATE-----
`)
)

func unixDialer(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", target, timeout)
}

func FetchSecrets(t *testing.T, udsPath string) *api.DiscoveryResponse {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithDialer(unixDialer))
	conn, err := grpc.Dial(udsPath, opts...)
	if err != nil {
		t.Fatalf("Failed to connect with server %v", err)
	}
	defer conn.Close()

	sleep := time.Duration(1) * time.Second
	for i := 0; i < 5; i++ {
		client := sds.NewSecretDiscoveryServiceClient(conn)
		response, err := client.FetchSecrets(context.Background(), &api.DiscoveryRequest{})
		if err == nil {
			return response
		}
		time.Sleep(sleep)
		log.Println("retrying after error:", err)
		sleep = sleep * 2
	}
	return nil
}

func VerifySecrets(t *testing.T, response *api.DiscoveryResponse) {
	if response == nil {
		t.Fatalf("failed to get response")
	}

	var secret auth.Secret
	resource := response.GetResources()[0]
	bytes := resource.Value

	err := proto.Unmarshal(bytes, &secret)
	if err != nil {
		t.Fatalf("failed parse the response %v", err)
	}

	if SecretTypeURL != response.GetTypeUrl() || SecretName != secret.GetName() {
		t.Fatalf("Unexpected response. Expected: type %s, name %s; Actual: type %s, name %s",
			SecretTypeURL, SecretName, response.GetTypeUrl(), secret.GetName())
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootCertBytes))
	if !ok {
		panic("failed to parse root certificate")
	}

	// Verify certificate and private key
	if _, err = tls.X509KeyPair(secret.GetTlsCertificate().CertificateChain.GetInlineBytes(),
		secret.GetTlsCertificate().PrivateKey.GetInlineBytes()); err != nil {
		t.Fatalf("failed to verify private key and certificate: %v", err)
	}

	block, _ := pem.Decode(secret.GetTlsCertificate().CertificateChain.GetInlineBytes())
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "ca.istio.io",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
}

func TestSingleUdsPath(t *testing.T) {
	server := NewSDSServer()

	bundle, err := util.NewVerifiedKeyCertBundleFromFile(
		"../../samples/plugin_ca_certs/ca-cert.pem", "../../samples/plugin_ca_certs/ca-key.pem",
		"../../samples/plugin_ca_certs/cert-chain.pem", "../../samples/plugin_ca_certs/root-cert.pem")
	if err != nil {
		t.Fatalf("failed to generate KeyCertBuldleFromPem")
	}
	_ = server.SetIdentityKeyCertBundle("test", bundle)

	tmpdir, _ := ioutil.TempDir("", "uds")
	defer func() {
		_ = os.RemoveAll(tmpdir)
	}()

	udsPath := filepath.Join(tmpdir, "test_path")

	if err := server.RegisterUdsPath(udsPath, "test"); err != nil {
		t.Fatalf("Unexpected Error: %v", err)
	}

	VerifySecrets(t, FetchSecrets(t, udsPath))

	if err := server.DeregisterUdsPath(udsPath); err != nil {
		t.Errorf("failed to deregister udsPath: %s (error: %v)", udsPath, err)
	}
}

func TestInvalidUdsPathIdentity(t *testing.T) {
	server := NewSDSServer()

	bundle, err := util.NewVerifiedKeyCertBundleFromFile(
		"../../samples/plugin_ca_certs/ca-cert.pem", "../../samples/plugin_ca_certs/ca-key.pem",
		"../../samples/plugin_ca_certs/cert-chain.pem", "../../samples/plugin_ca_certs/root-cert.pem")
	if err != nil {
		t.Fatalf("failed to generate KeyCertBuldleFromPem")
	}
	_ = server.SetIdentityKeyCertBundle("test", bundle)

	tmpdir, _ := ioutil.TempDir("", "uds")
	defer func() {
		_ = os.RemoveAll(tmpdir)
	}()
	udsPath := filepath.Join(tmpdir, "test_path")

	if err := server.RegisterUdsPath(udsPath, "invalid"); err == nil {
		t.Errorf("expected error")
	}
}

func TestMultipleUdsPaths(t *testing.T) {
	server := NewSDSServer()
	bundle, err := util.NewVerifiedKeyCertBundleFromFile(
		"../../samples/plugin_ca_certs/ca-cert.pem", "../../samples/plugin_ca_certs/ca-key.pem",
		"../../samples/plugin_ca_certs/cert-chain.pem", "../../samples/plugin_ca_certs/root-cert.pem")
	if err != nil {
		t.Fatalf("failed to generate KeyCertBuldleFromPem")
	}
	_ = server.SetIdentityKeyCertBundle("test1", bundle)
	_ = server.SetIdentityKeyCertBundle("test2", bundle)
	_ = server.SetIdentityKeyCertBundle("test3", bundle)

	tmpdir, _ := ioutil.TempDir("", "uds")
	udsPath1 := filepath.Join(tmpdir, "test_path1")
	udsPath2 := filepath.Join(tmpdir, "test_path2")
	udsPath3 := filepath.Join(tmpdir, "test_path3")

	err1 := server.RegisterUdsPath(udsPath1, "test1")
	err2 := server.RegisterUdsPath(udsPath2, "test2")
	err3 := server.RegisterUdsPath(udsPath3, "test3")
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("Unexpected Error: %v %v %v", err1, err2, err3)
	}

	VerifySecrets(t, FetchSecrets(t, udsPath1))
	VerifySecrets(t, FetchSecrets(t, udsPath2))
	VerifySecrets(t, FetchSecrets(t, udsPath3))

	if err := server.DeregisterUdsPath(udsPath1); err != nil {
		t.Errorf("failed to deregister udsPath: %s (error: %v)", udsPath1, err)
	}

	if err := server.DeregisterUdsPath(udsPath2); err != nil {
		t.Errorf("failed to deregister udsPath: %s (error: %v)", udsPath2, err)
	}

	if err := server.DeregisterUdsPath(udsPath3); err != nil {
		t.Errorf("failed to deregister udsPath: %s (error: %v)", udsPath3, err)
	}
}

func TestDuplicateUdsPaths(t *testing.T) {
	server := NewSDSServer()
	bundle, err := util.NewVerifiedKeyCertBundleFromFile(
		"../../samples/plugin_ca_certs/ca-cert.pem", "../../samples/plugin_ca_certs/ca-key.pem",
		"../../samples/plugin_ca_certs/cert-chain.pem", "../../samples/plugin_ca_certs/root-cert.pem")
	if err != nil {
		t.Fatalf("failed to generate KeyCertBuldleFromPem")
	}
	_ = server.SetIdentityKeyCertBundle("test", bundle)

	tmpdir, _ := ioutil.TempDir("", "uds")
	udsPath := filepath.Join(tmpdir, "test_path")

	_ = server.RegisterUdsPath(udsPath, "test")
	err = server.RegisterUdsPath(udsPath, "test")
	expectedErr := fmt.Sprintf("UDS path %v already exists", udsPath)
	if err == nil || err.Error() != expectedErr {
		t.Fatalf("Expect error: %v, Actual error: %v", expectedErr, err)
	}

	if err := server.DeregisterUdsPath(udsPath); err != nil {
		t.Errorf("failed to deregister udsPath: %s (error: %v)", udsPath, err)
	}
}
