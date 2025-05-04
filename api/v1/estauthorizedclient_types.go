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
	"crypto/x509/pkix"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ESTAuthorizedClientSpec defines the desired state of ESTAuthorizedClient.
type ESTAuthorizedClientSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Subject is the X.509 Distinguished Name (DN) of the client certificate.
	// It is used to identify the client when requesting a certificate from the EST server.
	// +kubebuilder:validation:Required
	Subject SubjectDN `json:"subject"`

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
	// +kubebuilder:default:=true
	CSRAutoApprove bool `json:"csrAutoApprove,omitempty"`

	// Duration is the duration for which the certificate will be valid.
	// +kubebuilder:default:="47d"
	Duration time.Duration `json:"duration,omitempty"`

	// AutoRenew indicates whether the certificate should be automatically renewed
	// when it is close to expiration. If set to true, the controller will
	// automatically renew the certificate before it expires.
	// If set to false, the certificate will not be automatically renewed.
	// This field defaults to true.
	// +kubebuilder:default:=true
	AutoRenew bool `json:"autoRenew,omitempty"`

	// RenewBefore is the duration before the certificate's expiration
	// when the certificate should be renewed.
	// +kubebuilder:default:="15d"
	RenewBefore time.Duration `json:"renewBefore,omitempty"`

	// RenewBeforePercentage is the percentage of the certificate's duration
	// when the certificate should be renewed. If both RenewBefore and
	// RenewBeforePercentage are set, the controller will use the earlier of the two.
	// +kubebuilder:default:=0.6
	RenewBeforePercentage float64 `json:"renewBeforePercentage,omitempty"`

	// RemoveExpired indicates whether expired certificates should be removed
	// from the Kubernetes cluster. If set to true, expired certificates will be
	// removed. If set to false, expired certificates will be retained.
	// This field defaults to true.
	// +kubebuilder:default:=true
	RemoveExpired bool `json:"removeExpired,omitempty"`
}

// SubjectDN represents the X.509 Distinguished Name (DN) of the certificate.
// It shares the same structure as pkix.Name, and additionally provides JSON tags.
type SubjectDN struct {
	// Country is the country (C) of the subject.
	Country []string `json:"country,omitempty"`
	// Organization is the organization (O) of the subject.
	Organization []string `json:"organization,omitempty"`
	// OrganizationalUnit is the organizational unit (OU) of the subject.
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	// Locality is the locality (L) of the subject.
	Locality []string `json:"locality,omitempty"`
	// Province is the province (ST) of the subject.
	Province []string `json:"province,omitempty"`
	// StreetAddress is the street address (street) of the subject.
	StreetAddress []string `json:"streetAddress,omitempty"`
	// PostalCode is the postal code (postalCode) of the subject.
	PostalCode []string `json:"postalCode,omitempty"`
	// CommonName is the common name (CN) of the subject.
	// It is a required field and must be set.
	// +kubebuilder:validation:Required
	CommonName string `json:"commonName"`
	// SerialNumber is the serial number (serialNumber) of the subject.
	SerialNumber string `json:"serialNumber,omitempty"`
}

// ToPKIXName converts the SubjectDN to a pkix.Name.
func (s SubjectDN) ToPKIXName() pkix.Name {
	return pkix.Name{
		Country:            s.Country,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Locality:           s.Locality,
		Province:           s.Province,
		StreetAddress:      s.StreetAddress,
		PostalCode:         s.PostalCode,
		CommonName:         s.CommonName,
	}
}

type PresharedKeyRef struct {
	// SecretName is the name of the secret that contains the pre-shared key.
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName"`
}

// ESTAuthorizedClientStatus defines the observed state of ESTAuthorizedClient.
type ESTAuthorizedClientStatus struct {
	// CurrentCSRName is the name of the latest CertificateSigningRequest.
	CurrentCSRName string `json:"latestCSRName,omitempty"`

	// PreviousCSRName is the name of the previous CertificateSigningRequest.
	PreviousCSRName string `json:"previousCSRName,omitempty"`

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
