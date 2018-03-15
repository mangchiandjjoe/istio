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
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"istio.io/istio/pkg/log"
	"istio.io/istio/security/pkg/pki/util"
)

type (
	// SecretServerInfo contains identity and grpc.Server instances for the UDS socket
	SecretServerInfo struct {
		// identity attached to the server
		identity string
		// grpc server instance
		server *grpc.Server
	}

	// SDSServer implements api.SecretDiscoveryServiceServer that listens on a
	// list of Unix Domain Sockets.
	SDSServer struct {
		// Stores the reference of the KeyCertBundle protected by identityKeyCertBundlGuard
		identityKeyCertBundles map[string]util.KeyCertBundle

		// Read/Write mutex for identityKeyCertBundles
		identityKeyCertBundlGuard sync.Mutex

		// Specifies a map of Unix Domain Socket paths and the SecretServerInfo.
		// Each UDS path identifies the identity for which the workload will
		// request X.509 key/cert from this server. This path should only be
		// accessible by such workload.
		udsServerMap map[string]*SecretServerInfo

		// Mutex for udsServerMap
		udsServerMapGuard sync.Mutex

		// current certificate chain and private key version number
		version string
	}
)

const (
	// key for UDS path in gRPC context metadata map.
	udsPathKey = ":authority"

	// SecretTypeURL defines the type URL for Envoy secret proto.
	SecretTypeURL = "type.googleapis.com/envoy.api.v2.auth.Secret"

	// SecretName defines the type of the secrets to fetch from the SDS server.
	SecretName = "SPKI"
)

// SetIdentityKeyCertBundle insert or update the KeyCertBundle and data version number, which is
// timestamp in milliseconds.
func (s *SDSServer) SetIdentityKeyCertBundle(identity string, bundle util.KeyCertBundle) error {
	s.identityKeyCertBundlGuard.Lock()
	defer s.identityKeyCertBundlGuard.Unlock()

	// Insert or update KeyCertBundle
	s.identityKeyCertBundles[identity] = bundle
	// Update data version
	// TODO(jaebong) for now we are using timestamp in milliseconds. It needs to be updated once we have a new design
	s.version = fmt.Sprintf("%v", time.Now().UnixNano()/int64(time.Millisecond))

	return nil
}

// GetTLSCertificate generates the X.509 key/cert for the workload identity
// derived from udsPath, which is where the FetchSecrets grpc request is
// received.
// SecretServer implementations could have different implementation
func (s *SDSServer) GetTLSCertificate(identity string) (*auth.TlsCertificate, error) {
	s.identityKeyCertBundlGuard.Lock()
	defer s.identityKeyCertBundlGuard.Unlock()

	keyCertBundle, ok := s.identityKeyCertBundles[identity]
	if !ok {
		return nil, fmt.Errorf("invalid identity")
	}

	cert, key, chain, root := keyCertBundle.GetAllPem()
	certificateChain := append(root, chain...)
	certificateChain = append(certificateChain, cert...)

	tlsSecret := &auth.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{certificateChain},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{key},
		},
	}

	return tlsSecret, nil
}

// FetchSecrets fetches the X.509 key/cert for a given workload whose identity
// can be derived from the UDS path where this call is received.
func (s *SDSServer) FetchSecrets(ctx context.Context, request *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	// Get the uds path where this call is received.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md[udsPathKey]) == 0 {
		errMessage := "unknown UDS path."
		log.Error(errMessage)
		return nil, status.Errorf(codes.Internal, errMessage)
	}

	udsPath := md[udsPathKey][0]

	serverInfo, ok := s.udsServerMap[udsPath]
	if !ok {
		errMessage := fmt.Sprintf("failed to read server info: %v", udsPath)
		log.Errorf(errMessage)
		return nil, status.Errorf(codes.Internal, errMessage)
	}

	tlsCertificate, err := s.GetTLSCertificate(serverInfo.identity)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read TLS certificate (%v)", err)
	}

	resources := make([]types.Any, 1)
	secret := &auth.Secret{
		Name: SecretName,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: tlsCertificate,
		},
	}
	data, err := proto.Marshal(secret)
	if err != nil {
		errMessage := fmt.Sprintf("Generates invalid secret (%v)", err)
		log.Errorf(errMessage)
		return nil, status.Errorf(codes.Internal, errMessage)
	}
	resources[0] = types.Any{
		TypeUrl: SecretTypeURL,
		Value:   data,
	}

	response := &api.DiscoveryResponse{
		Resources:   resources,
		TypeUrl:     SecretTypeURL,
		VersionInfo: s.version,
	}

	return response, nil
}

// StreamSecrets is not supported.
func (s *SDSServer) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	errMessage := "StreamSecrets is not implemented."
	log.Error(errMessage)
	return status.Errorf(codes.Unimplemented, errMessage)
}

// NewSDSServer creates the SDSServer that registers
// SecretDiscoveryServiceServer, a gRPC server.
func NewSDSServer() *SDSServer {
	s := &SDSServer{
		identityKeyCertBundles: map[string]util.KeyCertBundle{},
		udsServerMap:           map[string]*SecretServerInfo{},
		version:                fmt.Sprintf("%v", time.Now().UnixNano()/int64(time.Millisecond)),
	}

	return s
}

// RegisterUdsPath registers a path for Unix Domain Socket and has
// SDSServer's gRPC server listen on it.
func (s *SDSServer) RegisterUdsPath(udsPath, identity string) error {
	s.udsServerMapGuard.Lock()
	defer s.udsServerMapGuard.Unlock()

	s.identityKeyCertBundlGuard.Lock()
	defer s.identityKeyCertBundlGuard.Unlock()

	if _, ok := s.identityKeyCertBundles[identity]; !ok {
		return fmt.Errorf("invalid identity: %v", identity)
	}

	_, err := os.Stat(udsPath)
	if err == nil {
		return fmt.Errorf("UDS path %v already exists", udsPath)
	}

	listener, err := net.Listen("unix", udsPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %v", err)
	}

	var opts []grpc.ServerOption
	udsServer := grpc.NewServer(opts...)
	sds.RegisterSecretDiscoveryServiceServer(udsServer, s)
	s.udsServerMap[udsPath] = &SecretServerInfo{
		identity: identity,
		server:   udsServer,
	}

	// grpcServer.Serve() is a blocking call, so run it in a goroutine.
	go func() {
		log.Infof("Starting GRPC server on UDS path: %s", udsPath)
		err := udsServer.Serve(listener)
		// grpcServer.Serve() always returns a non-nil error.
		log.Warnf("GRPC server returns an error: %v", err)
	}()

	return nil
}

// DeregisterUdsPath closes and removes the grpcServer instance serving UDS
func (s *SDSServer) DeregisterUdsPath(udsPath string) error {
	s.udsServerMapGuard.Lock()
	defer s.udsServerMapGuard.Unlock()

	udsServer, ok := s.udsServerMap[udsPath]
	if !ok {
		return fmt.Errorf("udsPath is not registered: %s", udsPath)
	}

	udsServer.server.GracefulStop()
	delete(s.udsServerMap, udsPath)
	log.Infof("stopped the GRPC server on UDS path: %s", udsPath)

	// Remove the attached identity
	s.identityKeyCertBundlGuard.Lock()
	defer s.identityKeyCertBundlGuard.Unlock()
	delete(s.identityKeyCertBundles, udsServer.identity)

	return nil
}
