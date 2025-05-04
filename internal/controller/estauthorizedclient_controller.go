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

package controller

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certestuaryv1 "github.com/hsn723/cert-estuary/api/v1"
)

// ESTAuthorizedClientReconciler reconciles a ESTAuthorizedClient object
type ESTAuthorizedClientReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// workaround for https://github.com/kubernetes-sigs/controller-runtime/issues/550
	ReadClient client.Reader
}

// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients/finalizers,verbs=update
// +kubebuilder:rbac:groups="certificates.k8s.io",resources=certificatesigningrequests,verbs=get;list;create;delete
// +kubebuilder:rbac:groups="certificates.k8s.io",resources=certificatesigningrequests/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *ESTAuthorizedClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	eac := &certestuaryv1.ESTAuthorizedClient{}
	if err := r.Get(ctx, req.NamespacedName, eac); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if eac.ObjectMeta.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(eac, certestuaryv1.ESTAuthorizedClientFinalizer) {
			controllerutil.AddFinalizer(eac, certestuaryv1.ESTAuthorizedClientFinalizer)
			return ctrl.Result{}, r.Update(ctx, eac)
		}
	} else {
		logger.Info("finalizing ESTAuthorizedClient", "name", eac.Name)
		return ctrl.Result{}, r.finalize(ctx, eac)
	}

	return r.reconcile(ctx, eac)
}

func (r *ESTAuthorizedClientReconciler) hasOwnerReference(eac *certestuaryv1.ESTAuthorizedClient, ownerRefs []v1.OwnerReference) bool {
	for _, owner := range ownerRefs {
		if owner.APIVersion == certestuaryv1.GroupVersion.String() &&
			owner.Kind == certestuaryv1.EstAuthorizedClientKind &&
			owner.Name == eac.Name {
			return true
		}
	}
	return false
}

func (r *ESTAuthorizedClientReconciler) finalize(ctx context.Context, eac *certestuaryv1.ESTAuthorizedClient) error {
	if !controllerutil.ContainsFinalizer(eac, certestuaryv1.ESTAuthorizedClientFinalizer) {
		return nil
	}
	logger := logf.FromContext(ctx)
	csrList := &certsv1.CertificateSigningRequestList{}
	listOpts := &client.ListOptions{Namespace: eac.Namespace}
	if err := r.ReadClient.List(ctx, csrList, listOpts); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "failed to list CertificateSigningRequests")
		return err
	}
	for _, csr := range csrList.Items {
		if !r.hasOwnerReference(eac, csr.OwnerReferences) {
			continue
		}
		if err := r.Client.Delete(ctx, &csr); err != nil {
			logger.Error(err, "failed to delete CertificateSigningRequest", "name", csr.Name)
			return err
		}
		logger.Info("deleted CertificateSigningRequest", "name", csr.Name)
	}
	logger.Info("done finalizing", "name", eac.Name)
	controllerutil.RemoveFinalizer(eac, certestuaryv1.ESTAuthorizedClientFinalizer)
	return r.Update(ctx, eac)
}

func (r *ESTAuthorizedClientReconciler) reconcile(ctx context.Context, eac *certestuaryv1.ESTAuthorizedClient) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	if eac.Spec.RemoveExpired {
		logger.Info("removing expired certificates", "name", eac.Name)
		if needsUpdate := r.gc(ctx, eac); needsUpdate {
			return ctrl.Result{Requeue: true}, r.Status().Update(ctx, eac)
		}
	}
	// no CSRs have been received yet
	if eac.Status.CurrentCSRName == "" {
		return ctrl.Result{}, nil
	}

	csr := &certsv1.CertificateSigningRequest{}
	csrMeta := client.ObjectKey{
		Name:      eac.Status.CurrentCSRName,
		Namespace: eac.Namespace,
	}
	if err := r.ReadClient.Get(ctx, csrMeta, csr); err != nil {
		logger.Error(err, "failed to get CertificateSigningRequest", "name", eac.Status.CurrentCSRName)
		meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
			Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
			Status:  v1.ConditionFalse,
			Reason:  "CertificateSigningRequestNotFound",
			Message: "CertificateSigningRequest not found",
		})
		return ctrl.Result{Requeue: true}, r.Status().Update(ctx, eac)
	}
	// If auto-approve is enabled, approve the CSR
	if eac.Spec.CSRAutoApprove {
		if err := r.approveCSR(ctx, csr); err != nil {
			logger.Error(err, "failed to approve CertificateSigningRequest", "name", eac.Status.CurrentCSRName)
			return ctrl.Result{}, err
		}
	}
	// If the ESTAuthorizedClient is not ready, check the CSR status and update accordingly
	if meta.IsStatusConditionFalse(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) {
		if csr.Status.Certificate != nil {
			meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
				Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
				Status:  v1.ConditionTrue,
				Reason:  "CertificateReady",
				Message: "Certificate is ready",
			})
			return ctrl.Result{}, r.Status().Update(ctx, eac)
		}
	}
	// Now that everything is ready, check for renewal if enabled
	if eac.Spec.AutoRenew {
		return r.renewCert(ctx, eac, csr)
	}
	return ctrl.Result{}, nil
}

func (r *ESTAuthorizedClientReconciler) gc(ctx context.Context, eac *certestuaryv1.ESTAuthorizedClient) bool {
	logger := logf.FromContext(ctx)
	needsUpdate := false

	csrList := &certsv1.CertificateSigningRequestList{}
	listOpts := &client.ListOptions{Namespace: eac.Namespace}
	if err := r.ReadClient.List(ctx, csrList, listOpts); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "failed to list CertificateSigningRequests")
		return needsUpdate
	}
	for _, csr := range csrList.Items {
		if !r.hasOwnerReference(eac, csr.OwnerReferences) {
			continue
		}
		certDER := csr.Status.Certificate
		if certDER == nil {
			continue
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			logger.Error(err, "failed to parse certificate", "name", csr.Name)
			continue
		}
		if cert.NotAfter.After(time.Now()) {
			continue
		}
		if eac.Status.CurrentCSRName == csr.Name {
			eac.Status.CurrentCSRName = ""
			meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
				Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
				Status:  v1.ConditionFalse,
				Reason:  "CertificateExpired",
				Message: "Certificate is expired",
			})
			needsUpdate = true
		}
		if err := r.Client.Delete(ctx, &csr); err != nil {
			logger.Error(err, "failed to delete CertificateSigningRequest", "name", csr.Name)
			continue
		}
		logger.Info("deleted CertificateSigningRequest", "name", csr.Name)
	}
	return needsUpdate
}

func (r *ESTAuthorizedClientReconciler) approveCSR(ctx context.Context, csr *certsv1.CertificateSigningRequest) error {
	if csr.Status.Conditions == nil {
		csr.Status.Conditions = []certsv1.CertificateSigningRequestCondition{}
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certsv1.CertificateSigningRequestCondition{
		Type:    certsv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: "Auto approved by ESTAuthorizedClient controller",
	})
	return r.Client.Status().Update(ctx, csr)
}

func (r *ESTAuthorizedClientReconciler) getRenewThreshold(eac *certestuaryv1.ESTAuthorizedClient, cert *x509.Certificate) time.Time {
	threshold := cert.NotAfter.Add(-eac.Spec.RenewBefore)
	durationFromPercentage := time.Duration(eac.Spec.Duration.Seconds() * (1 - eac.Spec.RenewBeforePercentage)) * time.Second
	percentThreshold := cert.NotAfter.Add(-durationFromPercentage)
	if percentThreshold.Before(threshold) {
		return percentThreshold
	}
	return threshold
}

func (r *ESTAuthorizedClientReconciler) renewCert(ctx context.Context, eac *certestuaryv1.ESTAuthorizedClient, csr *certsv1.CertificateSigningRequest) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	certDER := csr.Status.Certificate
	if certDER == nil {
		logger.Info("no certificate in the CSR, skipping renewal", "name", csr.Name)
		return ctrl.Result{}, nil
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		logger.Error(err, "failed to parse certificate", "name", csr.Name)
		return ctrl.Result{}, err
	}
	threshold := r.getRenewThreshold(eac, cert)
	if time.Now().Before(threshold) {
		logger.Info("certificate is not up for renewal", "name", csr.Name, "threshold", threshold)
		return ctrl.Result{}, nil
	}

	newCSR := &certsv1.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", eac.Name, time.Now().Unix()),
			Namespace: eac.Namespace,
		},
		Spec: certsv1.CertificateSigningRequestSpec{
			Request:    csr.Spec.Request,
			SignerName: csr.Spec.SignerName,
			Usages:     csr.Spec.Usages,
			ExpirationSeconds: ptr.To(int32(eac.Spec.Duration.Seconds())),
		},
	}
	if err := controllerutil.SetControllerReference(eac, newCSR, r.Scheme); err != nil {
		logger.Error(err, "failed to set controller reference", "name", newCSR.Name)
		return ctrl.Result{}, err
	}
	if err := r.Client.Create(ctx, newCSR); err != nil {
		logger.Error(err, "failed to create CertificateSigningRequest", "name", newCSR.Name)
		return ctrl.Result{}, err
	}
	logger.Info("created CertificateSigningRequest", "name", newCSR.Name)
	eac.Status.PreviousCSRName = eac.Status.CurrentCSRName
	eac.Status.CurrentCSRName = newCSR.Name
	meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
		Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
		Status:  v1.ConditionFalse,
		Reason:  "CertificateRenewing",
		Message: "Certificate is being renewed",
	})
	return ctrl.Result{Requeue: true}, r.Status().Update(ctx, eac)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ESTAuthorizedClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certestuaryv1.ESTAuthorizedClient{}).
		Named("estauthorizedclient").
		Owns(&certsv1.CertificateSigningRequest{}).
		Complete(r)
}
