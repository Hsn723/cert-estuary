package estserver

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/fullsailor/pkcs7"
	certestuaryv1 "github.com/hsn723/cert-estuary/api/v1"
	certsv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type PEMType string

const (
	// PEMTypeCertificate is the PEM type for a certificate.
	PEMTypeCertificate PEMType = "CERTIFICATE"
	// PEMTypeCSR is the PEM type for a Certificate Signing Request (CSR).
	PEMTypeCSR PEMType = "CERTIFICATE REQUEST"
)

func getRequestID(r *http.Request) string {
	requestID := r.Context().Value(RequestIDContextKey)
	if requestID != nil {
		return requestID.(string)
	}
	return r.Header.Get("X-Request-ID")
}

func (s *ESTServer) decodeCSR(r *http.Request) (x509.CertificateRequest, ESTError) {
	buf := s.pool.Get().(*bytes.Buffer)
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return x509.CertificateRequest{}, ESTError{
			Error: err,
			Code:  http.StatusBadRequest,
		}
	}
	csr, err := x509.ParseCertificateRequest(buf.Bytes())
	if err != nil {
		return x509.CertificateRequest{}, ESTError{
			Error: err,
			Code:  http.StatusBadRequest,
		}
	}
	buf.Reset()
	s.pool.Put(buf)
	if err := csr.CheckSignature(); err != nil {
		return x509.CertificateRequest{}, ESTError{
			Error: err,
			Code:  http.StatusBadRequest,
		}
	}
	return *csr, ESTError{}
}

func (s *ESTServer) areCSRsIdentical(csr x509.CertificateRequest, clusterCSR certsv1.CertificateSigningRequest) bool {
	block := &pem.Block{
		Type:  string(PEMTypeCSR),
		Bytes: csr.Raw,
	}
	pemCSR := pem.EncodeToMemory(block)
	return bytes.Equal(clusterCSR.Spec.Request, pemCSR)
}

// findAuthenticatedClient finds the client that is authenticated by the CSR.
// A match is  found if the common name of the CSR matches the common name of the ESTAuthorizedClient.
func (s *ESTServer) findAuthenticatedClient(ctx context.Context, csr x509.CertificateRequest) (*certestuaryv1.ESTAuthorizedClient, ESTError) {
	eacList := certestuaryv1.ESTAuthorizedClientList{}
	if err := s.Options.Client.List(ctx, &eacList); err != nil {
		return nil, UnauthorizedError
	}
	for _, eac := range eacList.Items {
		if eac.Spec.Subject == csr.Subject.CommonName {
			return &eac, ESTError{}
		}
	}
	return nil, UnauthorizedError
}

func (s *ESTServer) authenticateClientCert(eac certestuaryv1.ESTAuthorizedClient, cert x509.Certificate) error {
	if _, err := cert.Verify(x509.VerifyOptions{}); err != nil {
		return err
	}
	if cert.Subject.CommonName != eac.Spec.Subject {
		return fmt.Errorf("client certificate common name does not match ESTAuthorizedClient")
	}
	return nil
}

func (s *ESTServer) retrieveRequestContext(r *http.Request) (x509.CertificateRequest, *certestuaryv1.ESTAuthorizedClient, ESTError) {
	csr, ok := r.Context().Value(csrContextKey).(x509.CertificateRequest)
	if !ok {
		return x509.CertificateRequest{}, nil, ESTError{
			Error: fmt.Errorf("failed to retrieve CSR from request context"),
			Code:  http.StatusInternalServerError,
		}
	}
	eac, ok := r.Context().Value(eacContextKey).(*certestuaryv1.ESTAuthorizedClient)
	if !ok {
		return x509.CertificateRequest{}, nil, ESTError{
			Error: fmt.Errorf("failed to retrieve ESTAuthorizedClient from request context"),
			Code:  http.StatusInternalServerError,
		}
	}
	return csr, eac, ESTError{}
}

func (s *ESTServer) pemToDER(pemCert []byte, pemType PEMType) []byte {
	var derCerts []byte
	for {
		block, rest := pem.Decode(pemCert)
		if block == nil {
			break
		}
		if block.Type == string(pemType) {
			derCerts = append(derCerts, block.Bytes...)
		}
		pemCert = rest
	}
	return derCerts
}

func (s *ESTServer) encodePKCS7Response(pemCert []byte) ([]byte, ESTError) {
	derCerts := s.pemToDER(pemCert, PEMTypeCertificate)
	if len(derCerts) == 0 {
		return nil, NoCertificatesFoundError
	}
	p7c, err := pkcs7.DegenerateCertificate(derCerts)
	if err != nil {
		return nil, CertificateEncodingError
	}
	return p7c, ESTError{}
}

func (s *ESTServer) createCertificateSigningRequest(ctx context.Context, csr x509.CertificateRequest, eac *certestuaryv1.ESTAuthorizedClient) ESTError {
	csrName := eac.GenerateCSRName()
	block := &pem.Block{
		Type:  string(PEMTypeCSR),
		Bytes: csr.Raw,
	}
	pemCSR := pem.EncodeToMemory(block)
	clusterCSR := certsv1.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name:      csrName,
			Namespace: eac.Namespace,
		},
		Spec: certsv1.CertificateSigningRequestSpec{
			Request:    pemCSR,
			SignerName: eac.Spec.SignerName,
			Usages: []certsv1.KeyUsage{
				certsv1.UsageServerAuth,
				certsv1.UsageClientAuth,
			},
			ExpirationSeconds: ptr.To(int32(eac.Spec.Duration.Seconds())),
		},
	}
	ownerRefOpts := controllerutil.WithBlockOwnerDeletion(true)
	if err := controllerutil.SetControllerReference(eac, &clusterCSR, s.Options.Scheme, ownerRefOpts); err != nil {
		s.Options.Logger.Error(err, "failed to set owner reference", "name", eac.Name, "csr", clusterCSR.Name)
		return CreateCSRFailedError
	}
	if err := s.Options.Client.Create(ctx, &clusterCSR); err != nil {
		s.Options.Logger.Error(err, "failed to create CertificateSigningRequest", "name", eac.Name, "csr", clusterCSR.Name)
		return CreateCSRFailedError
	}
	s.Options.Logger.Info("created CertificateSigningRequest", "name", eac.Name, "csr", clusterCSR.Name)
	if eac.Status.CurrentCSRName != "" {
		// Update the previous CSR name.
		eac.Status.PreviousCSRName = eac.Status.CurrentCSRName
	}
	// Update the current CSR status.
	eac.Status.CurrentCSRName = csrName
	meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
		Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
		Status:  v1.ConditionFalse,
		Reason:  "CertificatePending",
		Message: "CertificateSigningRequest has been created and is pending approval",
	})
	if err := s.Options.Client.Status().Update(ctx, eac); err != nil {
		s.Options.Logger.Error(err, "failed to update ESTAuthorizedClient status", "name", eac.Name)
		return CreateCSRFailedError
	}
	return NotReadyError
}

func (s *ESTServer) retrieveCSR(ctx context.Context, name, namespace string) (*certsv1.CertificateSigningRequest, error) {
	clusterCSR := &certsv1.CertificateSigningRequest{}
	csrObjectKey := client.ObjectKey{
		Name:      name,
		Namespace: namespace,
	}
	if err := s.Options.Client.Get(ctx, csrObjectKey, clusterCSR); err != nil {
		return nil, err
	}
	return clusterCSR, nil
}

func (s *ESTServer) doSimpleEnroll(ctx context.Context, csr x509.CertificateRequest, eac *certestuaryv1.ESTAuthorizedClient) ([]byte, ESTError) {
	if meta.IsStatusConditionFalse(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) {
		return nil, NotReadyError
	}
	if eac.Status.CurrentCSRName == "" {
		// CSR is not yet created, create it.
		return nil, s.createCertificateSigningRequest(ctx, csr, eac)
	}
	clusterCSR, err := s.retrieveCSR(ctx, eac.Status.CurrentCSRName, eac.Namespace)
	if err != nil {
		return nil, NoCertificatesFoundError
	}
	// Make sure the CSR matches the request.
	if !s.areCSRsIdentical(csr, *clusterCSR) {
		return nil, CSRMismatchError
	}
	if clusterCSR.Status.Certificate == nil {
		return nil, NotReadyError
	}
	return s.encodePKCS7Response(clusterCSR.Status.Certificate)
}

func (s *ESTServer) doSimpleReenroll(ctx context.Context, csr x509.CertificateRequest, eac *certestuaryv1.ESTAuthorizedClient) ([]byte, ESTError) {
	if meta.IsStatusConditionFalse(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) {
		return nil, NotReadyError
	}
	currentCSR, err := s.retrieveCSR(ctx, eac.Status.CurrentCSRName, eac.Namespace)
	if err != nil {
		return nil, NoCertificateToRenewError
	}
	if currentCSR.Status.Certificate == nil {
		return nil, NotReadyError
	}
	certDER := s.pemToDER(currentCSR.Status.Certificate, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, CertificateEncodingError
	}
	if !bytes.Equal(cert.RawSubject, csr.RawSubject) {
		return nil, CertificateMismatchError
	}
	if !slices.Equal(cert.DNSNames, csr.DNSNames) {
		return nil, CertificateMismatchError
	}
	// If the public keys do not match, it is a rekey request.
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, s.createCertificateSigningRequest(ctx, csr, eac)
	}
	if !s.areCSRsIdentical(csr, *currentCSR) {
		return nil, s.createCertificateSigningRequest(ctx, csr, eac)
	}
	// If the certificate has not been already renewed, renew it.
	previousCSR, err := s.retrieveCSR(ctx, eac.Status.PreviousCSRName, eac.Namespace)
	if client.IgnoreNotFound(err) != nil {
		return nil, NoCertificatesFoundError
	}
	if previousCSR == nil {
		return nil, s.createCertificateSigningRequest(ctx, csr, eac)
	}
	previousCertDER := s.pemToDER(previousCSR.Status.Certificate, PEMTypeCertificate)
	prevCert, err := x509.ParseCertificate(previousCertDER)
	if err != nil {
		return nil, NoCertificatesFoundError
	}
	// If the previous certificate is already expired, process CSR.
	if prevCert.NotAfter.Before(time.Now()) {
		return nil, s.createCertificateSigningRequest(ctx, csr, eac)
	}
	// If the previous certificate is not yet expired, the currrent certificate is necessarily a renewed one.
	// So we can return the current certificate.
	return s.encodePKCS7Response(currentCSR.Status.Certificate)
}
