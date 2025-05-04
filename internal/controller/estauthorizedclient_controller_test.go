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
	"fmt"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certestuaryv1 "github.com/hsn723/cert-estuary/api/v1"
)

var (
	dummyCSR = []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIChTCCAW0CAQAwHzEdMBsGA1UEAxMUZGVtb3N0ZXA0IDEzNjgxNDEzNTIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClNp+kdz+Nj8XpEp9kaumWxDZ3
eFYJpQKz9ddD5e5OzUeCm103ZIXQIxc0eVtMCatnRr3dnZRCAxGjwbqoB3eKt29/
XSQffVv+odbyw0WdkQOIbntCQry8YdcBZ+8LjI/N7M2krmjmoSLmLwU2V4aNKf0Y
MLR5Krmah3Ik31jmYCSvwTnv6mx6pr2pTJ82JavhTEIIt/fAYq1RYhkM1CXoBL+y
hEoDanN7TzC94skfS3VV+f53J9SkUxTYcy1Rw0k3VXfxWwy+cSKEPREl7I6k0YeK
tDEVAgBIEYM/L1S69RXTLujirwnqSRjOquzkAkD31BE961KZCxeYGrhxaR4PAgMB
AAGgITAfBgkqhkiG9w0BCQcxEhMQK3JyQ2lyLzcrRVl1NTBUNDANBgkqhkiG9w0B
AQUFAAOCAQEARBv0AJeXaHpl1MFIdzWqoi1dOCf6U+qaYWcBzpLADvJrPK1qx5pq
wXM830A1O+7RvrFv+nyd6VF2rl/MrNp+IsKuA9LYWIBjVe/LXoBO8dB/KxrYl16c
VUS+Yydi1m/a+DaftYSRGolMLtWeiqbc2SDBr2kHXW1TR130hIcpwmr29kC2Kzur
5thsuj276FGL1vPu0dRfGQfx4WWa9uAHBgz6tW37CepZsrUKe/0pfVhr2oHxApYh
cHGBQDQHVTFVjHccdUjAXicrtbsVhU5o1lPv7f4lEApv3SBQmJcaq5O832BzHw7n
PyMFcM15E9gtUVee5C62bVwuk/tbnGsbwQ==
-----END CERTIFICATE REQUEST-----`)

	dummyCert = []byte(`-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIJAOmuncOaM7IRMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV
BAMTEGVzdEV4YW1wbGVDQSBOd04wHhcNMTMwNTA5MDM1MzMyWhcNMTQwNTA5MDM1
MzMyWjAbMRkwFwYDVQQDExBlc3RFeGFtcGxlQ0EgTndOMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAnn3rZ3rMJHwf7MD9K4mubxHAvtdnrsQf5OfgtMhR
IL4aePNhAdgPyj8CloxOgD3UTV+dQ1ViOzVxPN7acikoOnkIdRpjpOpkyMo+KkvH
MQXGnQTbsMAv1qWt9S12DMpo0GOA1e4Ge3ud5YPOTR/q6PvjN51IEwYKksG7Cglw
ZwB+5JbwhYr2D/0ubtGltriRVixPWrvt+wz/ITp5rcjh/8RS3LE8tQy3kTNhJF3Y
/esR2sSgOiPNgItoCATysbaINEPr4MemqML4tDpR/aG9y+8Qe7s1LyMFvDletp2m
mBykAC/7nOat/pwUlB0sN524D1XAgz8ZKvWrkh+ZaOr3hwIDAQABo0IwQDAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBSxxGnmW6MEp9iXo4s7v7lqsjJCPDAOBgNV
HQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggEBAELP8JZ1i+cYz9J0J0SKibkD
VXFpbycqAJaD8TJa0AiJodC5WIH6NNQAT2WidrYxsmgUdbxTl7z10I/SsmkD1Rhd
eFa8VDN3llamazjBRi3WPeCqp3foqiskgC4+KBWeDXfIrK3EztxWbFCeHRq7HdoS
cTJEYCEZqUenRFop2A9HNRoa2KklM0GRJXlLiQPjIMI8cw1sG745yW56vASlvPoa
8TsKleXaOtMFlKoGwV6WrSLPiST3770KfBnCtWB3OSWFF8nVniM2Quu7BtD6jg28
FmxeIrE1+fcrajdIrwC5oTINaSrXz7muNx+mtE7zHhhNb7qZc+qMzQwAY0MRb7U=
-----END CERTIFICATE-----`)
)

func isCSRStatusApproved(csr *certsv1.CertificateSigningRequest) bool {
	if csr.Status.Conditions == nil {
		return false
	}
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certsv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func setupTestReconciler(mgr manager.Manager) *ESTAuthorizedClientReconciler {
	kubeClient := kubernetes.NewForConfigOrDie(cfg)
	reconciler := &ESTAuthorizedClientReconciler{
		Client:     k8sClient,
		Scheme:     k8sClient.Scheme(),
		KubeClient: kubeClient,
		ReadClient: k8sClient,
		Metrics:    estuaryMetrics,
	}
	Expect(reconciler.SetupWithManager(context.TODO(), mgr)).To(Succeed())
	return reconciler
}

func createTestNamespace(ctx context.Context) string {
	By("creating namespace")
	namespace := uuid.NewString()
	namespaceMeta := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}
	Expect(k8sClient.Create(ctx, namespaceMeta)).NotTo(HaveOccurred())
	return namespace
}

func createTestEAC(name, namespace string, autoApprove bool) {
	By("creating the custom resource for the Kind ESTAuthorizedClient")
	resource := &certestuaryv1.ESTAuthorizedClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: certestuaryv1.ESTAuthorizedClientSpec{
			Subject:        "test-client",
			SignerName:     "issuers.cert-manager.io/default.test-issuer",
			CSRAutoApprove: autoApprove,
		},
	}
	Expect(k8sClient.Create(ctx, resource)).To(Succeed())
}

var _ = Describe("ESTAuthorizedClient Controller", func() {
	Context("When reconciling a resource", func() {
		var stopFunc func()
		var mgr manager.Manager

		ctx := context.Background()

		BeforeEach(func() {
			By("settting up the manager")
			var err error
			mgr, err = ctrl.NewManager(cfg, ctrl.Options{
				Scheme:         scheme.Scheme,
				LeaderElection: false,
				Controller: config.Controller{
					SkipNameValidation: ptr.To(true),
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(mgr).NotTo(BeNil())
			mgrCtx, cancel := context.WithCancel(ctx)
			stopFunc = cancel
			go func() {
				err := mgr.Start(mgrCtx)
				if err != nil {
					panic(err)
				}
			}()
			time.Sleep(100 * time.Millisecond)
		})

		AfterEach(func() {
			stopFunc()
			time.Sleep(100 * time.Millisecond)
		})

		It("should not approve non-owned CSRs", func() {
			eac := &certestuaryv1.ESTAuthorizedClient{}
			namespace := createTestNamespace(ctx)
			eacName := uuid.NewString()
			csrName := fmt.Sprintf("%s-%d", eacName, time.Now().Unix())
			eacNamespacedName := types.NamespacedName{
				Name:      eacName,
				Namespace: namespace,
			}
			reconcileRequest := reconcile.Request{NamespacedName: eacNamespacedName}

			createTestEAC(eacName, namespace, true)

			By("Reconciling the created resource")
			reconciler := setupTestReconciler(mgr)
			_, err := reconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the status of the resources")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(eac.Status.CurrentCSRName).To(BeEmpty())

			By("Creating an independent CertificateSigningRequest")
			csrNamespacedName := types.NamespacedName{
				Name:      csrName,
				Namespace: namespace,
			}
			csr := &certsv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      csrName,
					Namespace: namespace,
				},
				Spec: certsv1.CertificateSigningRequestSpec{
					Request:    dummyCSR,
					SignerName: "issuers.cert-manager.io/default.test-issuer",
					Usages: []certsv1.KeyUsage{
						certsv1.UsageClientAuth,
						certsv1.UsageServerAuth,
					},
				},
			}
			Expect(k8sClient.Create(ctx, csr)).To(Succeed())

			By("By adding CSR to the resource")
			eac.Status.CurrentCSRName = csrName
			Expect(k8sClient.Status().Update(ctx, eac)).To(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(eac.Status.CurrentCSRName).To(Equal(csrName))
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())

			By("Reconciling the resource again")
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(k8sClient.Get(ctx, csrNamespacedName, csr)).NotTo(HaveOccurred())
			Expect(isCSRStatusApproved(csr)).To(BeFalse())
		})

		It("should successfully reconcile the resource", func() {
			eac := &certestuaryv1.ESTAuthorizedClient{}
			namespace := createTestNamespace(ctx)
			eacName := uuid.NewString()
			csrName := fmt.Sprintf("%s-%d", eacName, time.Now().Unix())
			eacNamespacedName := types.NamespacedName{
				Name:      eacName,
				Namespace: namespace,
			}
			reconcileRequest := reconcile.Request{NamespacedName: eacNamespacedName}

			createTestEAC(eacName, namespace, true)

			By("Reconciling the created resource")
			reconciler := setupTestReconciler(mgr)
			_, err := reconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the status of the resources")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(eac.Status.CurrentCSRName).To(BeEmpty())

			By("Creating a CertificateSigningRequest")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			csrNamespacedName := types.NamespacedName{
				Name:      csrName,
				Namespace: namespace,
			}
			csr := &certsv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      csrName,
					Namespace: namespace,
					Labels: map[string]string{
						certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel: eac.Name,
					},
				},
				Spec: certsv1.CertificateSigningRequestSpec{
					Request:    dummyCSR,
					SignerName: "issuers.cert-manager.io/default.test-issuer",
					Usages: []certsv1.KeyUsage{
						certsv1.UsageClientAuth,
						certsv1.UsageServerAuth,
					},
				},
			}
			Expect(k8sClient.Create(ctx, csr)).To(Succeed())

			By("By adding CSR to the resource")
			eac.Status.CurrentCSRName = csrName
			Expect(k8sClient.Status().Update(ctx, eac)).To(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(eac.Status.CurrentCSRName).To(Equal(csrName))
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())

			By("Checking the CSR status")
			Expect(k8sClient.Get(ctx, csrNamespacedName, csr)).NotTo(HaveOccurred())
			Expect(isCSRStatusApproved(csr)).To(BeFalse())

			By("Reconciling the resource again")
			_, err = reconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(k8sClient.Get(ctx, csrNamespacedName, csr)).NotTo(HaveOccurred())
			Expect(isCSRStatusApproved(csr)).To(BeTrue())

			By("Creating a dummy certificate")
			csr.Status.Certificate = dummyCert
			Expect(k8sClient.Status().Update(ctx, csr)).To(Succeed())

			By("Checking the updated resource")
			_, err = reconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeTrue())
		})

		It("should clear currentCSRName if the CSR does not exist", func() {
			eac := &certestuaryv1.ESTAuthorizedClient{}
			namespace := createTestNamespace(ctx)
			eacName := uuid.NewString()
			csrName := fmt.Sprintf("%s-%d", eacName, time.Now().Unix())
			eacNamespacedName := types.NamespacedName{
				Name:      eacName,
				Namespace: namespace,
			}
			reconcileRequest := reconcile.Request{NamespacedName: eacNamespacedName}
			createTestEAC(eacName, namespace, true)

			By("Reconciling the created resource")
			reconciler := setupTestReconciler(mgr)
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())

			By("Verifying the status of the resources")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(eac.Status.CurrentCSRName).To(BeEmpty())

			By("By adding CSR to the resource")
			eac.Status.CurrentCSRName = csrName
			Expect(k8sClient.Status().Update(ctx, eac)).To(Succeed())
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())
			getCSRName := func() string {
				err := k8sClient.Get(ctx, eacNamespacedName, eac)
				if err != nil {
					return "error"
				}
				return eac.Status.CurrentCSRName
			}
			Eventually(getCSRName, 5*time.Second, 1*time.Second).Should(BeEmpty())
			Consistently(getCSRName, 5*time.Second, 1*time.Second).Should(BeEmpty())
		})

		It("should not approve CSRs if auto-approve is disabled", func() {
			eac := &certestuaryv1.ESTAuthorizedClient{}
			namespace := createTestNamespace(ctx)
			eacName := uuid.NewString()
			csrName := fmt.Sprintf("%s-%d", eacName, time.Now().Unix())
			eacNamespacedName := types.NamespacedName{
				Name:      eacName,
				Namespace: namespace,
			}
			reconcileRequest := reconcile.Request{NamespacedName: eacNamespacedName}
			createTestEAC(eacName, namespace, false)

			By("Reconciling the created resource")
			reconciler := setupTestReconciler(mgr)
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())

			By("Verifying the status of the resources")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(eac.Status.CurrentCSRName).To(BeEmpty())
			Expect(eac.Spec.CSRAutoApprove).To(BeFalse())

			By("Creating a CertificateSigningRequest")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			csrNamespacedName := types.NamespacedName{
				Name:      csrName,
				Namespace: namespace,
			}
			csr := &certsv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      csrName,
					Namespace: namespace,
					Labels: map[string]string{
						certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel: eac.Name,
					},
				},
				Spec: certsv1.CertificateSigningRequestSpec{
					Request:    dummyCSR,
					SignerName: "issuers.cert-manager.io/default.test-issuer",
					Usages: []certsv1.KeyUsage{
						certsv1.UsageClientAuth,
						certsv1.UsageServerAuth,
					},
				},
			}
			Expect(k8sClient.Create(ctx, csr)).To(Succeed())

			By("By adding CSR to the resource")
			eac.Status.CurrentCSRName = csrName
			Expect(k8sClient.Status().Update(ctx, eac)).To(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(eac.Status.CurrentCSRName).To(Equal(csrName))
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())

			By("Checking the CSR status")
			Expect(k8sClient.Get(ctx, csrNamespacedName, csr)).NotTo(HaveOccurred())
			Expect(isCSRStatusApproved(csr)).To(BeFalse())

			By("Reconciling the resource again")
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(isCSRStatusApproved(csr)).To(BeFalse())
		})

		It("should finalize the resource", func() {
			eac := &certestuaryv1.ESTAuthorizedClient{}
			namespace := createTestNamespace(ctx)
			eacName := uuid.NewString()
			csrName := fmt.Sprintf("%s-%d", eacName, time.Now().Unix())
			eacNamespacedName := types.NamespacedName{
				Name:      eacName,
				Namespace: namespace,
			}
			reconcileRequest := reconcile.Request{NamespacedName: eacNamespacedName}
			createTestEAC(eacName, namespace, true)

			By("Reconciling the created resource")
			reconciler := setupTestReconciler(mgr)
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())

			By("Verifying the status of the resources")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(eac.Status.CurrentCSRName).To(BeEmpty())

			By("Creating a CertificateSigningRequest")
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			csrNamespacedName := types.NamespacedName{
				Name:      csrName,
				Namespace: namespace,
			}
			csr := &certsv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      csrName,
					Namespace: namespace,
					Labels: map[string]string{
						certestuaryv1.ESTAuthorizedClientOwnerReferenceLabel: eac.Name,
					},
				},
				Spec: certsv1.CertificateSigningRequestSpec{
					Request:    dummyCSR,
					SignerName: "issuers.cert-manager.io/default.test-issuer",
					Usages: []certsv1.KeyUsage{
						certsv1.UsageClientAuth,
						certsv1.UsageServerAuth,
					},
				},
			}
			Expect(k8sClient.Create(ctx, csr)).To(Succeed())

			By("By adding CSR to the resource")
			eac.Status.CurrentCSRName = csrName
			Expect(k8sClient.Status().Update(ctx, eac)).To(Succeed())
			Expect(k8sClient.Get(ctx, eacNamespacedName, eac)).NotTo(HaveOccurred())
			Expect(eac.Status.CurrentCSRName).To(Equal(csrName))
			Expect(meta.IsStatusConditionTrue(eac.Status.Conditions, certestuaryv1.ESTAuthorizedClientConditionTypeReady)).To(BeFalse())
			Expect(k8sClient.Get(ctx, csrNamespacedName, csr)).NotTo(HaveOccurred())

			By("Reconciling the resource again")
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, reconcileRequest)
				return err
			}, 5*time.Second, 1*time.Second).Should(Succeed())

			By("Deleting the resource")
			Expect(k8sClient.Delete(ctx, eac)).To(Succeed())
			Eventually(func() error {
				err := k8sClient.Get(ctx, eacNamespacedName, eac)
				if err != nil {
					return err
				}
				return nil
			}, 5*time.Second, 1*time.Second).Should(HaveOccurred())
			Eventually(func() error {
				err := k8sClient.Get(ctx, csrNamespacedName, csr)
				if err != nil {
					return err
				}
				return nil
			}, 5*time.Second, 1*time.Second).Should(HaveOccurred())
		})
	})
})
