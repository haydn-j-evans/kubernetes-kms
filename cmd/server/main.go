// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/haydn-j-evans/kubernetes-kms/pkg/metrics"
	"github.com/haydn-j-evans/kubernetes-kms/pkg/plugin"
	"github.com/haydn-j-evans/kubernetes-kms/pkg/utils"
	"github.com/haydn-j-evans/kubernetes-kms/pkg/version"

	"google.golang.org/grpc"
	"k8s.io/klog/v2"
	kmsv1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
	"monis.app/mlog"
)

var (
	listenAddr   = flag.String("listen-addr", "unix:///opt/azurekms.socket", "gRPC listen address")
	keyvaultName = flag.String("keyvault-name", "", "Hashicorp Key Vault name")

	logFormatJSON = flag.Bool("log-format-json", false, "set log formatter to json")
	logLevel      = flag.Int("v", 0, "In order of increasing verbosity: 0=warning/error, 2=info, 4=debug, 6=trace, 10=all")

	keyName         = flag.String("key-name", "", "Key Vault KMS key name")
	keyVersion      = flag.String("key-version", "", "Key Vault KMS key version")
	keyVaultAddress = flag.String("address", "http://localhost:8200", "Key Vault KMS key address")

	keyVaultToken           = flag.String("token", "", "Key Vault KMS key token")
	keyVaultAppRoleRoleID   = flag.String("approle-role-id", "", "Key Vault KMS key app role id")
	keyVaultAppRoleSecretID = flag.String("approle-secret-id", "", "Key Vault KMS key app secret id")

	// CACert is the path to a PEM-encoded CA cert file to use to verify the
	// Vault server SSL certificate.
	keyVaultCAFilePath = flag.String("ca-file", "", "Key Vault KMS key CA file")
	keyVaultClientCert = flag.String("client-cert", "", "Key Vault KMS key client certificate")
	keyVaultClientKey  = flag.String("client-key", "", "Key Vault KMS key client key")

	// TLSServerName, if set, is used to set the SNI host when connecting via TLS.
	keyVaultTLSServerName = flag.String("tls-server-name", "", "Key Vault KMS key tls server name")
	keyVaultTransitPath   = flag.String("transit-path", "transit", "Key Vault KMS key transit path")
	keyVaultAuthPath      = flag.String("auth-path", "auth", "Key Vault KMS key auth path")

	versionInfo = flag.Bool("version", false, "Prints the version information")

	healthzPort    = flag.Int("healthz-port", 8787, "port for health check")
	healthzPath    = flag.String("healthz-path", "/healthz", "path for health check")
	healthzTimeout = flag.Duration("healthz-timeout", 20*time.Second, "RPC timeout for health check")
	metricsBackend = flag.String("metrics-backend", "prometheus", "Backend used for metrics")
	metricsAddress = flag.String("metrics-addr", "8095", "The address the metric endpoint binds to")

	proxyMode    = flag.Bool("proxy-mode", false, "Proxy mode")
	proxyAddress = flag.String("proxy-address", "", "proxy address")
	proxyPort    = flag.Int("proxy-port", 7788, "port for proxy")
)

func main() {
	if err := setupKMSPlugin(); err != nil {
		mlog.Fatal(err)
	}
}

func setupKMSPlugin() error {
	defer mlog.Setup()() // set up log flushing and attempt to flush on exit
	flag.Parse()
	ctx := withShutdownSignal(context.Background())

	logFormat := mlog.FormatText
	if *logFormatJSON {
		logFormat = mlog.FormatJSON
	}

	if err := mlog.ValidateAndSetKlogLevelAndFormatGlobally(ctx, klog.Level(*logLevel), logFormat); err != nil {
		return fmt.Errorf("invalid --log-level set: %w", err)
	}

	if *versionInfo {
		if err := version.PrintVersion(); err != nil {
			return fmt.Errorf("failed to print version: %w", err)
		}
		return nil
	}

	// initialize metrics exporter
	err := metrics.InitMetricsExporter(*metricsBackend, *metricsAddress)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics exporter: %w", err)
	}

	mlog.Always("Starting KeyManagementServiceServer service", "version", version.BuildVersion, "buildDate", version.BuildDate)

	pluginConfig := &plugin.Config{
		KeyVaultName:            *keyvaultName,
		KeyName:                 *keyName,
		KeyVersion:              *keyVersion,
		KeyVaultAddress:         *keyVaultAddress,
		KeyVaultToken:           *keyVaultToken,
		KeyVaultAppRoleRoleID:   *keyVaultAppRoleRoleID,
		KeyVaultAppRoleSecretID: *keyVaultAppRoleSecretID,
		KeyVaultCAFilePath:      *keyVaultCAFilePath,
		KeyVaultClientCert:      *keyVaultClientCert,
		KeyVaultClientKey:       *keyVaultClientKey,
		KeyVaultTLSServerName:   *keyVaultTLSServerName,
		KeyVaultTransitPath:     *keyVaultTransitPath,
		KeyVaultAuthPath:        *keyVaultAuthPath,
		ProxyMode:               *proxyMode,
		ProxyAddress:            *proxyAddress,
		ProxyPort:               *proxyPort,
	}

	kvClient, err := plugin.New(pluginConfig)
	if err != nil {
		return fmt.Errorf("failed to create key vault client: %w", err)
	}

	// Initialize and run the GRPC server
	proto, addr, err := utils.ParseEndpoint(*listenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove socket file %s: %w", addr, err)
	}

	listener, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("failed to listen addr: %s, proto: %s: %w", addr, proto, err)
	}

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(utils.UnaryServerInterceptor),
	}

	s := grpc.NewServer(opts...)

	// register kms v1 server
	kmsV1Server, err := plugin.NewKMSv1Server(kvClient)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	kmsv1.RegisterKeyManagementServiceServer(s, kmsV1Server)

	// register kms v2 server
	kmsV2Server, err := plugin.NewKMSv2Server(kvClient)
	if err != nil {
		return fmt.Errorf("failed to create kms V2 server: %w", err)
	}
	kmsv2.RegisterKeyManagementServiceServer(s, kmsV2Server)

	mlog.Always("Listening for connections", "addr", listener.Addr().String())
	go func() {
		if err := s.Serve(listener); err != nil {
			mlog.Fatal(fmt.Errorf("failed to serve kms server: %w", err))
		}
	}()

	// Health check for kms v1 and v2
	healthz := &plugin.HealthZ{
		KMSv1Server: kmsV1Server,
		KMSv2Server: kmsV2Server,
		HealthCheckURL: &url.URL{
			Host: net.JoinHostPort("", strconv.FormatUint(uint64(*healthzPort), 10)),
			Path: *healthzPath,
		},
		UnixSocketPath: listener.Addr().String(),
		RPCTimeout:     *healthzTimeout,
	}
	go healthz.Serve()

	<-ctx.Done()
	// gracefully stop the grpc server
	mlog.Always("terminating the server")
	s.GracefulStop()

	return nil
}

// withShutdownSignal returns a copy of the parent context that will close if
// the process receives termination signals.
func withShutdownSignal(ctx context.Context) context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

	nctx, cancel := context.WithCancel(ctx)

	go func() {
		<-signalChan
		mlog.Always("received shutdown signal")
		cancel()
	}()
	return nctx
}
