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

	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	certestuaryv1 "github.com/hsn723/cert-estuary/api/v1"
)

// ESTAuthorizedClientReconciler reconciles a ESTAuthorizedClient object
type ESTAuthorizedClientReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	KubeClient kubernetes.Interface
	Queue      chan reconcile.Request
	// workaround for https://github.com/kubernetes-sigs/controller-runtime/issues/550
	ReadClient client.Reader
}

// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-estuary.atelierhsn.com,resources=estauthorizedclients/finalizers,verbs=update
// +kubebuilder:rbac:groups="certificates.k8s.io",resources=certificatesigningrequests,verbs=get;list;watch;create;delete;approve
// +kubebuilder:rbac:groups="certificates.k8s.io",resources=certificatesigningrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="certificates.k8s.io",resources=certificatesigningrequests/approval,verbs=update
// +kubebuilder:rbac:groups="cert-manager.io",resources=signers,verbs=reference,resourceNames="*"

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

func (r *ESTAuthorizedClientReconciler) isOwnedCSR(eac *certestuaryv1.ESTAuthorizedClient, csr certsv1.CertificateSigningRequest) bool {
	owner, ok := csr.Labels[certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel]
	if !ok {
		return false
	}
	return owner == eac.Name
}

func (r *ESTAuthorizedClientReconciler) finalize(ctx context.Context, eac *certestuaryv1.ESTAuthorizedClient) error {
	if !controllerutil.ContainsFinalizer(eac, certestuaryv1.ESTAuthorizedClientFinalizer) {
		return nil
	}
	logger := logf.FromContext(ctx)
	csrList := &certsv1.CertificateSigningRequestList{}
	listOpts := &client.ListOptions{
		Namespace: eac.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel: eac.Name,
		}),
	}
	if err := r.ReadClient.List(ctx, csrList, listOpts); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "failed to list CertificateSigningRequests")
		return err
	}
	for _, csr := range csrList.Items {
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
	// no CSRs have been received yet
	if eac.Status.CurrentCSRName == "" {
		if meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) {
			meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
				Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
				Status:  v1.ConditionFalse,
				Reason:  "CertificateSigningRequestPending",
				Message: "CertificateSigningRequest is pending creation",
			})
			return ctrl.Result{}, r.Status().Update(ctx, eac)
		}
		return ctrl.Result{}, nil
	}

	csr := &certsv1.CertificateSigningRequest{}
	csrMeta := client.ObjectKey{
		Name:      eac.Status.CurrentCSRName,
		Namespace: eac.Namespace,
	}
	if err := r.ReadClient.Get(ctx, csrMeta, csr); err != nil {
		var reason, message string
		var requeue bool
		if client.IgnoreNotFound(err) != nil {
			logger.Error(err, "failed to get CertificateSigningRequest", "name", eac.Status.CurrentCSRName)
			requeue = true
			reason = "CertificateSigningRequestNotFound"
			message = "CertificateSigningRequest not found"
		} else {
			logger.Info("CertificateSigningRequest has been deleted", "name", eac.Status.CurrentCSRName)
			eac.Status.CurrentCSRName = ""
			reason = "CertificateSigningRequestPending"
			message = "CertificateSigningRequest is pending creation"
		}
		meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
			Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
			Status:  v1.ConditionFalse,
			Reason:  reason,
			Message: message,
		})
		return ctrl.Result{Requeue: requeue}, r.Status().Update(ctx, eac)
	}
	if !r.isOwnedCSR(eac, *csr) {
		logger.Info("CertificateSigningRequest does not have the owner reference, skipping", "name", csr.Name)
		meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
			Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
			Status:  v1.ConditionFalse,
			Reason:  "InvalidCertificateSigningRequest",
			Message: "CertificateSigningRequest not owned by ESTAuthorizedClient",
		})
		return ctrl.Result{}, r.Status().Update(ctx, eac)
	}
	// If auto-approve is enabled, approve the CSR
	if eac.Spec.CSRAutoApprove {
		if err := r.approveCSR(ctx, csr); err != nil {
			logger.Error(err, "failed to approve CertificateSigningRequest", "name", eac.Status.CurrentCSRName)
			return ctrl.Result{}, err
		}
	}
	// Make sure the status is up to date, for instance when the CSR has just been created.
	// If the ESTAuthorizedClient is not ready, check the CSR status and update accordingly.
	if meta.FindStatusCondition(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) == nil ||
		meta.IsStatusConditionFalse(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady) {
		if csr.Status.Certificate != nil {
			meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
				Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
				Status:  v1.ConditionTrue,
				Reason:  "CertificateReady",
				Message: "Certificate is ready",
			})
			return ctrl.Result{}, r.Status().Update(ctx, eac)
		}
		// Sanity: if the CSR is not approved yet, set the status to false
		meta.SetStatusCondition(&eac.Status.Conditions, v1.Condition{
			Type:    certestuaryv1.ESTAuthorizedClientConditionTypeReady,
			Status:  v1.ConditionFalse,
			Reason:  "CertificateSigningRequestPending",
			Message: "CertificateSigningRequest is pending",
		})
		return ctrl.Result{Requeue: true}, r.Status().Update(ctx, eac)
	}
	return ctrl.Result{}, nil
}

// controller-runtime does not support certificatesigningrequests/approval,
// so we must use UpdateApproval() directly.
func (r *ESTAuthorizedClientReconciler) approveCSR(ctx context.Context, csr *certsv1.CertificateSigningRequest) error {
	for _, c := range csr.Status.Conditions {
		if c.Type == certsv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			// Already approved, no need to approve again
			return nil
		}
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certsv1.CertificateSigningRequestCondition{
		Type:    certsv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: "Auto approved by ESTAuthorizedClient controller",
	})
	_, err := r.KubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, v1.UpdateOptions{})
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *ESTAuthorizedClientReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	r.Queue = make(chan reconcile.Request, 1000)
	err := mgr.GetFieldIndexer().IndexField(ctx, &certsv1.CertificateSigningRequest{}, ".metadata.controller", func(rawObj client.Object) []string {
		csr := rawObj.(*certsv1.CertificateSigningRequest)
		owner, ok := csr.Labels[certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel]
		if !ok {
			return nil
		}
		return []string{owner}
	})
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&certestuaryv1.ESTAuthorizedClient{}).
		Named("estauthorizedclient").
		Owns(&certsv1.CertificateSigningRequest{}).
		Complete(r)
}
