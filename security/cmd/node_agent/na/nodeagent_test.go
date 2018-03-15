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

package na

import (
	"fmt"
	"os"
	"testing"
	"time"

	"istio.io/istio/pkg/log"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/platform"
	mockpc "istio.io/istio/security/pkg/platform/mock"
	"istio.io/istio/security/pkg/util"
	mockutil "istio.io/istio/security/pkg/util/mock"
	"istio.io/istio/security/pkg/workload"
	pb "istio.io/istio/security/proto"
)

const (
	maxMockCAClientSuccessReturns = 3
)

type MockCAClient struct {
	certChainFile   string
	signingCertFile string
	signingKeyFile  string
	rootCertFile    string
	Response        *pb.CsrResponse
	Err             error
	Counter         int
}

func (f *MockCAClient) SendCSR(req *pb.CsrRequest, pc platform.Client, addr string) (*pb.CsrResponse, error) {
	if f.Counter >= maxMockCAClientSuccessReturns {
		return nil, fmt.Errorf("terminating the test with errors")
	}

	f.Counter++

	if f.Response != nil || f.Err != nil {
		return f.Response, f.Err
	}

	defaultWorkloadCertTTL := 30 * time.Minute
	maxWorkloadCertTTL := time.Hour

	caopts, err := ca.NewPluggedCertIstioCAOptions(f.certChainFile, f.signingCertFile, f.signingKeyFile, f.rootCertFile,
		defaultWorkloadCertTTL, maxWorkloadCertTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create a plugged-cert CA Options: %v", err)
	}

	istioca, err := ca.NewIstioCA(caopts)
	if err != nil {
		return nil, fmt.Errorf("got error while createing plugged-cert CA: %v", err)
	}
	if istioca == nil {
		return nil, fmt.Errorf("failed to create a plugged-cert CA")
	}

	_, _, chain, _ := istioca.GetCAKeyCertBundle().GetAll()

	cert, err := istioca.Sign(req.CsrPem, defaultWorkloadCertTTL, false)
	if err != nil {
		return nil, fmt.Errorf("failed to sign. (%v)", err)
	}

	return &pb.CsrResponse{
		IsApproved: true,
		SignedCert: cert,
		CertChain:  chain,
	}, nil
}

// MockFileUtil is a mocked FileUtil for testing.
type MockFileUtil struct {
	Content map[string][]byte
}

// Read returns the filename entry in ReadContent or an error.
func (f MockFileUtil) Read(filename string) ([]byte, error) {
	if f.Content[filename] != nil {
		return f.Content[filename], nil
	}
	return nil, fmt.Errorf("file not found")
}

// Write writes data to the filename entry in WriteContent.
func (f MockFileUtil) Write(filename string, content []byte, perm os.FileMode) error {
	if f.Content == nil {
		f.Content = make(map[string][]byte)
	}
	f.Content[filename] = content
	return nil
}

func TestStartWithArgs(t *testing.T) {
	generalConfig := Config{
		IstioCAAddress:     "ca_addr",
		ServiceIdentityOrg: "Google Inc.",
		RSAKeySize:         512,
		Env:                "onprem",
		CSRInitialRetrialInterval: time.Millisecond,
		CSRMaxRetries:             3,
		CSRGracePeriodPercentage:  50,
		LoggingOptions:            log.DefaultOptions(),
		RootCertFile:              "../../../samples/plugin_ca_certs/root-cert.pem",
		KeyFile:                   "../../../samples/plugin_ca_certs/ca-key.pem",
		CertChainFile:             "../../../samples/plugin_ca_certs/ca-cert.pem",
	}

	testCases := map[string]struct {
		config      *Config
		pc          platform.Client
		cAClient    *MockCAClient
		certUtil    util.CertUtil
		expectedErr string
		sendTimes   int
		fileContent []string
	}{
		"Success": {
			config: &generalConfig,
			pc:     mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient: &MockCAClient{
				certChainFile:   "../../../samples/plugin_ca_certs/cert-chain.pem",
				signingCertFile: "../../../samples/plugin_ca_certs/ca-cert.pem",
				signingKeyFile:  "../../../samples/plugin_ca_certs/ca-key.pem",
				rootCertFile:    "../../../samples/plugin_ca_certs/root-cert.pem",
			},
			certUtil:    mockutil.FakeCertUtil{time.Duration(10), nil},
			expectedErr: "node agent can't get the CSR approved from Istio CA after max number of retries (3)",
			sendTimes:   3,
			fileContent: []string{
				"/service1/cert.pem",
				"/service1/key.pem",
				"/service1/chain.pem",
				"/service1/root.pem",
			},
		},
		"Config Nil error": {
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{},
			expectedErr: "node Agent configuration is nil",
			sendTimes:   0,
		},
		"Platform error": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", false},
			cAClient:    &MockCAClient{},
			expectedErr: "node Agent is not running on the right platform",
			sendTimes:   0,
		},
		"Create CSR error": {
			// 128 is too small for a RSA private key. GenCSR will return error.
			config: &Config{
				IstioCAAddress:     "ca_addr",
				ServiceIdentityOrg: "Google Inc.",
				RSAKeySize:         128,
				Env:                "onprem",
				CSRInitialRetrialInterval: time.Millisecond,
				CSRMaxRetries:             3,
				CSRGracePeriodPercentage:  50,
				RootCertFile:              "../../../samples/plugin_ca_certs/root-cert.pem",
				KeyFile:                   "../../../samples/plugin_ca_certs/ca-key.pem",
				CertChainFile:             "../../../samples/plugin_ca_certs/ca-cert.pem",
				LoggingOptions:            log.DefaultOptions(),
			},
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{},
			expectedErr: "CSR creation failed (crypto/rsa: message too long for RSA public key size)",
			sendTimes:   0,
		},
		"Getting agent credential error": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", nil, "Err1", true},
			cAClient:    &MockCAClient{},
			expectedErr: "request creation fails on getting agent credential (Err1)",
			sendTimes:   0,
		},
		"SendCSR empty response error": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{},
			expectedErr: "node agent can't get the CSR approved from Istio CA after max number of retries (3)",
			sendTimes:   3,
		},
		"SendCSR returns error": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{Err: fmt.Errorf("error returned from CA")},
			expectedErr: "node agent can't get the CSR approved from Istio CA after max number of retries (3)",
			sendTimes:   3,
		},
		"SendCSR not approved": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{Response: &pb.CsrResponse{IsApproved: false}},
			expectedErr: "node agent can't get the CSR approved from Istio CA after max number of retries (3)",
			sendTimes:   3,
		},
		"SendCSR parsing error": {
			config:      &generalConfig,
			pc:          mockpc.FakeClient{nil, "", "service1", "", []byte{}, "", true},
			cAClient:    &MockCAClient{Response: &pb.CsrResponse{IsApproved: true, SignedCert: []byte{}, CertChain: []byte{}}},
			certUtil:    mockutil.FakeCertUtil{time.Duration(0), fmt.Errorf("cert parsing error")},
			expectedErr: "node agent can't get the CSR approved from Istio CA after max number of retries (3)",
			sendTimes:   3,
		},
	}

	for id, c := range testCases {
		log.Errorf("Start to test %s", id)

		fakeFileUtil := MockFileUtil{
			Content: make(map[string][]byte),
		}

		fakeWorkloadIO, _ := workload.NewSecretServer(
			workload.Config{
				Mode:               workload.SecretFile,
				FileUtil:           fakeFileUtil,
				ServiceIdentityDir: "",
			},
		)
		na := nodeAgentInternal{c.config, c.pc, c.cAClient, "service1", fakeWorkloadIO, c.certUtil}
		err := na.Start()
		if err.Error() != c.expectedErr {
			t.Errorf("Test case [%s]: incorrect error message: %s VS (expected) %s", id, err.Error(), c.expectedErr)
		}

		if c.cAClient.Counter != c.sendTimes {
			t.Errorf("Test case [%s]: sendCSR is called incorrect times: %d VS (expected) %d",
				id, c.cAClient.Counter, c.sendTimes)
		}

		for _, path := range c.fileContent {
			if _, err := fakeFileUtil.Read(path); err != nil {
				t.Errorf(err.Error())
			}
		}
	}
}
