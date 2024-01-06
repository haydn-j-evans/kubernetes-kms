// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"sync"

	"github.com/haydn-j-evans/kubernetes-kms/pkg/utils"
	"github.com/haydn-j-evans/kubernetes-kms/pkg/version"

	vaultapi "github.com/hashicorp/vault/api"

	"k8s.io/klog/v2"
	"k8s.io/kms/pkg/service"
	"monis.app/mlog"
)

// encryptionResponseVersion is validated prior to decryption.
// This is helpful in case we want to change anything about the data we send in the future.
var encryptionResponseVersion = "1"

// Handle all communication with Vault server.
type vaultWrapper struct {
	client      *vaultapi.Client
	encryptPath string
	decryptPath string
	authPath    string
	rwmutex     sync.RWMutex
	config      *Config
	keyIDHash   string
}

// Client interface for interacting with Keyvault.
type Client interface {
	Encrypt(
		ctx context.Context,
		plain []byte,
	) (*service.EncryptResponse, error)
	Decrypt(
		ctx context.Context,
		cipher []byte,
		apiVersion string,
		annotations map[string][]byte,
		decryptRequestKeyID string,
	) ([]byte, error)
	//GetUserAgent() string
	//GetVaultURL() string
}

// New creates an instance of the KMS client.
func New(vaultConfig *Config) (Client, error) {

	client, err := newClientWrapper(vaultConfig)
	if err != nil {
		mlog.Error("Unable to create vault client", err)
	}

	return client, nil
}

// newClientWrapper initialize a client wrapper for vault kms provider.
func newClientWrapper(vaultConfig *Config) (*vaultWrapper, error) {
	mlog.Debug("Initialize client wrapper...")

	client, err := newVaultAPIClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create vault client: %w", err)
	}

	keyIDHash, err := getKeyIDHash(vaultConfig.KeyVaultAddress, vaultConfig.KeyName, vaultConfig.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("unable to get key id hash: %w", err)
	}

	wrapper := &vaultWrapper{
		client:      client,
		encryptPath: path.Join("v1", vaultConfig.KeyVaultTransitPath, "encrypt"),
		decryptPath: path.Join("v1", vaultConfig.KeyVaultTransitPath, "decrypt"),
		authPath:    path.Join(vaultConfig.KeyVaultAuthPath),
		config:      vaultConfig,
		keyIDHash:   keyIDHash,
	}

	// Set token for the vaultapi.client.
	if vaultConfig.KeyVaultToken != "" {
		mlog.Debug("Setting token for the vault client...", utils.SecretToLog(vaultConfig.KeyVaultToken))
		client.SetToken(vaultConfig.KeyVaultToken)
	} else {
		mlog.Debug("Getting initial token...", "transit", vaultConfig.KeyVaultTransitPath, "auth", vaultConfig.KeyVaultAuthPath)

		if err := wrapper.getInitialToken(vaultConfig); err != nil {
			mlog.Error("Unable to get initial token", err, "transit", vaultConfig.KeyVaultTransitPath, "auth", vaultConfig.KeyVaultAuthPath)
			return nil, fmt.Errorf("unable to get initial token: %w", err)
		}
	}

	return wrapper, nil
}

func newVaultAPIClient(vaultConfig *Config) (*vaultapi.Client, error) {
	mlog.Info("Configuring TLS...")

	defaultConfig := vaultapi.DefaultConfig()
	defaultConfig.Address = vaultConfig.KeyVaultAddress

	tlsConfig := &vaultapi.TLSConfig{
		CACert:        vaultConfig.KeyVaultCAFilePath,
		ClientCert:    vaultConfig.KeyVaultClientCert,
		ClientKey:     vaultConfig.KeyVaultClientKey,
		TLSServerName: vaultConfig.KeyVaultTLSServerName,
	}
	if err := defaultConfig.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("unable to configure TLS for %s: %w", vaultConfig.KeyVaultTLSServerName, err)
	}

	mlog.Info("Initializing API client...")

	return vaultapi.NewClient(defaultConfig)
}

func (c *vaultWrapper) getInitialToken(vaultConfig *Config) error {
	switch {
	case vaultConfig.KeyVaultClientCert != "" && vaultConfig.KeyVaultClientKey != "":
		mlog.Info("Get initial token by:", "cert", vaultConfig.KeyVaultClientCert, "key", vaultConfig.KeyVaultClientKey)

		token, err := c.tlsToken()
		if err != nil {
			return fmt.Errorf("rotating token through TLS auth backend: %w", err)
		}

		c.client.SetToken(token)

	case vaultConfig.KeyVaultAppRoleRoleID != "":
		mlog.Info("Get initial token by:", "role", vaultConfig.KeyVaultAppRoleRoleID)

		token, err := c.appRoleToken(vaultConfig)
		if err != nil {
			return fmt.Errorf("rotating token through app role backend: %w", err)
		}

		c.client.SetToken(token)

	default:
		// configuration has already been validated, flow should not reach here
		return errors.New("the Vault authentication configuration is invalid")
	}

	return nil
}

func (c *vaultWrapper) tlsToken() (string, error) {

	loginPath := path.Join("/", c.authPath, "cert", "login")

	mlog.Info("Get TLS token...", "path", loginPath)

	resp, err := c.client.Logical().Write(loginPath, nil)
	if err != nil {
		return "", fmt.Errorf("unable to write TLS via API on %s: %w", loginPath, err)
	} else if resp.Auth == nil {
		return "", errors.New("authentication information not found")
	}

	return resp.Auth.ClientToken, nil
}

func (c *vaultWrapper) appRoleToken(vaultConfig *Config) (string, error) {

	data := map[string]interface{}{
		"role_id":   vaultConfig.KeyVaultAppRoleRoleID,
		"secret_id": vaultConfig.KeyVaultAppRoleSecretID,
	}
	loginPath := path.Join("/", c.authPath, "approle", "login")

	mlog.Info("Get app role token...", "path", loginPath, "role_id", vaultConfig.KeyVaultAppRoleRoleID, "secret_id", utils.SecretToLog(vaultConfig.KeyVaultAppRoleSecretID))

	resp, err := c.client.Logical().Write(loginPath, data)
	if err != nil {
		return "", fmt.Errorf("unable to write app role token via API on %s: %w", loginPath, err)
	} else if resp.Auth == nil {
		return "", errors.New("authentication information not found")
	}

	return resp.Auth.ClientToken, nil
}

// Encrypt encrypts input.
func (c *vaultWrapper) Encrypt(ctx context.Context, data []byte) (*service.EncryptResponse, error) {
	mlog.Info("Encrypting...")

	mlog.Info("Encrypting data...", "key", c.config.KeyName, "data", utils.SecretToLog(string(data)))

	response, err := c.withRefreshToken(true, c.config.KeyName, data)
	if err != nil {
		mlog.Error("Unable to encrypt data", err)
		return nil, fmt.Errorf("unable to encrypt data: %w", err)
	}

	mlog.Info("Encrypted data...", "key", c.config.KeyName, "data", utils.SecretToLog(response))

	encryptionResponse := &service.EncryptResponse{
		Ciphertext:  []byte(response),
		KeyID:       c.config.KeyName,
		Annotations: nil,
	}
	return encryptionResponse, nil
}

// Decrypt decrypts input.
func (c *vaultWrapper) Decrypt(ctx context.Context, data []byte, apiVersion string, annotations map[string][]byte, decryptRequestKeyID string) ([]byte, error) {
	mlog.Debug("Decrypting...")

	mlog.Debug("Decrypting data...", "key", c.config.KeyName, "data", utils.SecretToLog(string(data)))

	response, err := c.withRefreshToken(false, c.config.KeyName, data)
	if err != nil {
		klog.InfoS("Unable to decrypt data", "error", err.Error())
		return nil, fmt.Errorf("unable to decrypt data: %w", err)
	}

	mlog.Debug("Decrypted data...", "key", c.config.KeyName, "data", utils.SecretToLog(response))

	return []byte(response), nil
}

func (c *vaultWrapper) request(requestPath string, data interface{}) (*vaultapi.Secret, error) {
	mlog.Debug("Sending request...", "path", requestPath)

	req := c.client.NewRequest("POST", "/"+requestPath)
	if err := req.SetJSONBody(data); err != nil {
		return nil, fmt.Errorf("unable to set request JSON on %s: %w", requestPath, err)
	}

	//nolint:staticcheck // we know RawRequest is deprecated
	resp, err := c.client.RawRequest(req)
	if err != nil {
		code := -1
		if resp != nil {
			code = resp.StatusCode
		}

		klog.InfoS("Failed to send request", "code", code, "error", err.Error())

		if code == http.StatusForbidden {
			return nil, newForbiddenError(err)
		}

		return nil, fmt.Errorf("error making POST request on %s: %w", requestPath, err)
	} else if resp == nil {
		return nil, fmt.Errorf("no response received for POST request on %s: %w", requestPath, err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			klog.ErrorS(err, "Failed to close body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %v received for POST request to %v", resp.StatusCode, requestPath)
	}

	mlog.Debug("Parsing secret...")

	return vaultapi.ParseSecret(resp.Body)
}

func (c *vaultWrapper) Version() error {
	return version.PrintVersion()
}

func (c *vaultWrapper) withRefreshToken(isEncrypt bool, key string, data []byte) (string, error) {
	// Execute operation first time.
	var (
		result string
		err    error
	)

	func() {
		c.rwmutex.RLock()
		defer c.rwmutex.RUnlock()

		if isEncrypt {
			result, err = c.encryptLocked(key, data)
		} else {
			result, err = c.decryptLocked(key, data)
		}
	}()

	if err == nil || c.config.KeyVaultToken != "" {
		return result, nil
	}

	if _, ok := err.(*forbiddenError); !ok {
		return result, fmt.Errorf("error during connection for %s: %w", key, err)
	}

	c.rwmutex.Lock()
	defer c.rwmutex.Unlock()

	mlog.Debug("Refreshing token...")

	if err = c.refreshTokenLocked(c.config); err != nil {
		klog.Error(err, "Failed to refresh token")
		return result, fmt.Errorf("error refresh token request: %w", err)
	}

	mlog.Debug("Token refreshed...")

	if isEncrypt {
		result, err = c.encryptLocked(key, data)
	} else {
		result, err = c.decryptLocked(key, data)
	}

	if err != nil {
		klog.InfoS("Error during en/de-cryption", "isEncrypt", isEncrypt, "key", key)
		err = fmt.Errorf("error during en/de-cryption for %s: %w", key, err)
	}

	return result, err
}

func (c *vaultWrapper) refreshTokenLocked(vaultConfig *Config) error {
	return c.getInitialToken(vaultConfig)
}

func (c *vaultWrapper) encryptLocked(key string, data []byte) (string, error) {
	mlog.Debug("Encrypting locked...", "key", key)

	dataReq := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(data)}

	resp, err := c.request(path.Join(c.encryptPath, key), dataReq)
	if err != nil {
		klog.InfoS("Failed to encrypt locked", "key", key, "error", err.Error())
		return "", fmt.Errorf("error during encrypt request for %s: %w", key, err)
	}

	result, ok := resp.Data["ciphertext"].(string)
	if !ok {
		klog.InfoS("Failed to find ciphertext", "key", key)
		return result, fmt.Errorf("failed type assertion of vault encrypt response type for %s: %v to string", key, reflect.TypeOf(resp.Data["ciphertext"]))
	}

	return base64.StdEncoding.EncodeToString([]byte(result)), nil
}

func (c *vaultWrapper) decryptLocked(_ string, data []byte) (string, error) {
	mlog.Debug("Decrypting locked...")

	chiphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		klog.InfoS("Failed decode encrypted data", "error", err.Error())
		return "", fmt.Errorf("failed decode encrypted data: %w", err)
	}

	dataReq := map[string]string{"ciphertext": string(chiphertext)}

	resp, err := c.request(path.Join(c.decryptPath, c.config.KeyName), dataReq)
	if err != nil {
		klog.InfoS("Failed to decrypt locked", "error", err.Error())
		return "", fmt.Errorf("error during decrypt request: %w", err)
	}

	result, ok := resp.Data["plaintext"].(string)
	if !ok {
		klog.InfoS("Failed to find plaintext representation")
		return "", fmt.Errorf("failed type assertion of vault decrypt response type: %v to string", reflect.TypeOf(resp.Data["plaintext"]))
	}

	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		klog.InfoS("Failed decode encrypted data", "error", err.Error())
		return "", fmt.Errorf("failed decode encrypted data: %w", err)
	}

	return string(decoded), nil
}

//func (kvc *KeyVaultClient) GetUserAgent() string {
//	return kvc.baseClient.UserAgent
//}

//func (kvc *KeyVaultClient) GetVaultURL() string {
//	return kvc.vaultURL
//}

func getKeyIDHash(vaultURL, keyName, keyVersion string) (string, error) {
	if vaultURL == "" || keyName == "" || keyVersion == "" {
		return "", fmt.Errorf("vault url, key name and key version cannot be empty")
	}

	baseURL, err := url.Parse(vaultURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse vault url, error: %w", err)
	}

	urlPath := path.Join("keys", keyName, keyVersion)
	keyID := baseURL.ResolveReference(
		&url.URL{
			Path: urlPath,
		},
	).String()

	return fmt.Sprintf("%x", sha256.Sum256([]byte(keyID))), nil
}
