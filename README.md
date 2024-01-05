# KMS Plugin for Key Vault

[![Build Status](https://dev.azure.com/AzureContainerUpstream/Kubernetes%20KMS/_apis/build/status/Kubernetes%20KMS%20CI?branchName=master)](https://dev.azure.com/AzureContainerUpstream/Kubernetes%20KMS/_build/latest?definitionId=442&branchName=master)
[![Go Report Card](https://goreportcard.com/badge/Azure/kubernetes-kms)](https://goreportcard.com/report/Azure/kubernetes-kms)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/Azure/kubernetes-kms)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/Azure/kubernetes-kms)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Azure/kubernetes-kms/badge)](https://api.securityscorecards.dev/projects/github.com/Azure/kubernetes-kms)

Enables encryption at rest of your Kubernetes data in etcd using Hashicorp Vault.

From the Kubernetes documentation on [Encrypting Secret Data at Rest]:

> _[KMS Plugin for Key Vault is]_ the recommended choice for using a third party tool for key management. Simplifies key rotation, with a new data encryption key (DEK) generated for each encryption, and key encryption key (KEK) rotation controlled by the user.

⚠️ **NOTE**: Currently, KMS plugin for Key Vault does not support key rotation. If you create a new key version in KMS, decryption will fail since it won't match the key used for encryption when the cluster was created.

## Features

- Use a key in Key Vault for etcd encryption
- Use a key in Key Vault protected by a Hardware Security Module (HSM)
- Bring your own keys
- Store secrets, keys, and certs in etcd, but manage them as part of Kubernetes

## Getting Started

### Prerequisites

💡 Make sure you have a Kubernetes cluster version 1.10 or later, the minimum version that is supported by KMS Plugin for Key Vault.

### Setting up KMS Plugin manually

Refer to [doc](docs/manual-install.md) for steps to setup the KMS Key Vault plugin on an existing cluster.

## Verifying that Data is Encrypted

Now that Vault KMS provider is running in your cluster and the encryption configuration is setup, it will encrypt the data in etcd. Let's verify that is working:

1. Create a new secret:

   ```bash
   kubectl create secret generic secret1 -n default --from-literal=mykey=mydata
   ```

2. Using `etcdctl`, read the secret from etcd:

   ```bash
   sudo ETCDCTL_API=3 etcdctl --cacert=/etc/kubernetes/certs/ca.crt --cert=/etc/kubernetes/certs/etcdclient.crt --key=/etc/kubernetes/certs/etcdclient.key get /registry/secrets/default/secret1
   ```

3. Check that the stored secret is prefixed with `k8s:enc:kms:v1:azurekmsprovider` when KMSv1 is used for encryption, or with `k8s:enc:kms:v2:azurekmsprovider` when KMSv2 is used. This prefix indicates that the data has been encrypted by the Azure KMS provider.

4. Verify the secret is decrypted correctly when retrieved via the Kubernetes API:

   ```bash
   kubectl get secrets secret1 -o yaml
   ```

   The output should match `mykey: bXlkYXRh`, which is the encoded data of `mydata`.

## Rotation

Refer to [doc](docs/rotation.md) for steps to rotate the KMS Key on an existing cluster.

## Metrics
Refer to [doc](docs/metrics.md) for details on the metrics exposed by the KMS Key Vault plugin.

## Code of conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

