/*
Copyright 2025 Hsn723.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ESTAuthorizedClientFinalizer is the finalizer for ESTAuthorizedClient resources.
	ESTAuthorizedClientFinalizer = "cert-estuary.atelierhsn.com/finalizer"

	// ESTAuthorizedClientLabel is the label for ESTAuthorizedClient resources.
	// Since CertificateSigningRequest resources are not namespaced, we need to use a label
	// to identify the ESTAuthorizedClient resource that created the CSR.
	ESTAuthorizedClientOwnerReferenceLabel = "cert-estuary.atelierhsn.com/estauthorizedclient"
)

// ESTAuthorizedClientSpec defines the desired state of ESTAuthorizedClient.
type ESTAuthorizedClientSpec struct {
	// Subject is the Common Name (CN) of the client certificate.
	// It is used to identify the client when requesting a certificate from the EST server.
	// +kubebuilder:validation:Required
	Subject string `json:"subject"`

	// SubjectAltNames is an optional field that allows you to specify additional
	// subject alternative names for the certificate. These names can be used to identify the client
	// in addition to the main subject DN.
	SubjectAltNames []string `json:"subjectAltNames,omitempty"`

	// PresharedKeyRef is a reference to a secret that contains the pre-shared key
	// used for authentication. The secret must be in the same namespace as the ESTAuthorizedClient resource.
	// The secret should contain a key named "username" for the username and "password" for the password.
	PresharedKeyRef PresharedKeyRef `json:"presharedKeyRef,omitempty"`

	// SignerName is the name of the Issuer or ClusterIssuer
	// that will be used to sign the certificate.
	// It should be in the format "issuers.cert-manager.io/<namespace>.<issuer-name>" or
	// "clusterissuers.cert-manager.io/<cluster-issuer-name>".
	// See https://cert-manager.io/docs/usage/kube-csr/#signer-name for more details.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(issuers|clusterissuers)\.cert-manager\.io/([a-z][a-z-]*\.)?[a-z][a-z-]*$`
	SignerName string `json:"signerName"`

	// CSRAutoApprove indicates whether the Certificate Signing Request (CSR) should be automatically approved.
	// If set to true, the CSR will be automatically approved by the controller.
	// If set to false, the CSR will need to be manually approved by a user with the appropriate permissions.
	// This field defaults to true.
	// +kubebuilder:default=true
	CSRAutoApprove bool `json:"csrAutoApprove"`

	// Duration is the duration for which the certificate will be valid.
	// Value must be in units accepted by Go time.ParseDuration https://golang.org/pkg/time/#ParseDuration.
	// +kubebuilder:default="1128h"
	Duration *metav1.Duration `json:"duration"`
}

type PresharedKeyRef struct {
	// SecretName is the name of the secret that contains the pre-shared key.
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`
}

const ESTAuthorizedClientConditionTypeReady = "Ready"

// ESTAuthorizedClientStatus defines the observed state of ESTAuthorizedClient.
type ESTAuthorizedClientStatus struct {
	// CurrentCSRName is the name of the latest CertificateSigningRequest.
	CurrentCSRName string `json:"latestCSRName,omitempty"`

	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ESTAuthorizedClient is the Schema for the estauthorizedclients API.
type ESTAuthorizedClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ESTAuthorizedClientSpec   `json:"spec,omitempty"`
	Status ESTAuthorizedClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ESTAuthorizedClientList contains a list of ESTAuthorizedClient.
type ESTAuthorizedClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ESTAuthorizedClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ESTAuthorizedClient{}, &ESTAuthorizedClientList{})
}

func (e ESTAuthorizedClient) GenerateCSRName() string {
	return fmt.Sprintf("%s-%d", e.Name, time.Now().Unix())
}
