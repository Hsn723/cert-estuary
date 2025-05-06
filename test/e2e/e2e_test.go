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

//nolint:lll
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/hsn723/cert-estuary/test/utils"
)

// namespace where the project is deployed in
const namespace = "cert-estuary-system"

// serviceAccountName created for the project
const serviceAccountName = "cert-estuary-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "cert-estuary-controller-manager-metrics-service"

const estServiceName = "cert-estuary-est-server"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "cert-estuary-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pods")
		cmd := exec.Command("kubectl", "delete", "pods", "-l", "app.kubernetes.io/name=curl", "-A")
		_, _ = utils.Run(cmd)

		By("deleting the client certificate")
		cmd = exec.Command("kubectl", "delete", "certificate", "est-client-cert", "-n", "default")
		_, _ = utils.Run(cmd)

		By("deleting all ESTAuthorizedClient resources")
		cmd = exec.Command("kubectl", "delete", "estauthorizedclient", "--all", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-logs")
			cmd = exec.Command("kubectl", "logs", "-l", "app.kubernetes.io/name=curl", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Curl logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure that the EST server is running", func() {
			By("validating that the EST service is available")
			cmd := exec.Command("kubectl", "get", "service", estServiceName, "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "EST service should exist")

			By("waiting for the EST endpoint to be ready")
			verifyEstEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", estServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("4443"), "EST endpoint is not ready")
			}
			Eventually(verifyEstEndpointReady).Should(Succeed())

			By("validating that the controller manager is serving the EST server")
			verifyEstServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("est-server\tstarting server"),
					"EST server not yet started")
			}
			Eventually(verifyEstServerStarted).Should(Succeed())

			By("creating the curl-est pod to access the EST endpoint")
			curlCommand := fmt.Sprintf(`"curl -v -k https://%s.%s.svc.cluster.local:4443/%s"`, estServiceName, namespace, ".well-known/est/cacerts")
			cmd = exec.Command("kubectl", "run", "curl-est-cacerts", "--restart=Never",
				"--namespace", "default",
				"--image=curlimages/curl:latest",
				"--labels", "app.kubernetes.io/name=curl",
				"--overrides",
				utils.GetCurlPodSpec(curlCommand, "default"))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-est pod")

			By("waiting for the curl-est pod to complete.")
			Eventually(verifyCurlUp, 5*time.Minute).WithArguments("curl-est-cacerts", "default").Should(Succeed())

			By("getting the EST server response by checking curl-est logs")
			expected := []string{
				"< HTTP/1.1 200 OK",
				"Content-Type: application/pkcs7-mime",
			}
			unexpected := []string{}
			_ = getESTOutput("curl-est-cacerts", "default", expected, unexpected)

			By("creating an ESTAuthorizedClient")
			cmd = exec.Command("kubectl", "apply", "-n", namespace, "-f", "./config/samples/cert-estuary_v1_estauthorizedclient.yaml")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ESTAuthorizedClient")

			By("making sure the ESTAuthorizedClient is created")
			verifyESTAuthorizedClientCreated := func(g Gomega, name string) {
				cmd := exec.Command("kubectl", "get", "estauthorizedclient", "-n", namespace, name)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(name), "ESTAuthorizedClient not created")
			}
			Eventually(verifyESTAuthorizedClientCreated).WithArguments("estauthorizedclient-sample").Should(Succeed())

			By("forwarding the EST server port to access the EST endpoint")
			portFwdCmd := exec.Command("kubectl", "port-forward", "-n", namespace, fmt.Sprintf("svc/%s", estServiceName), "4443:4443")
			err = portFwdCmd.Start()
			Expect(err).NotTo(HaveOccurred(), "Failed to start port-forwarding")
			defer func() {
				_ = portFwdCmd.Process.Kill()
			}()

			By("retrieving the issuer cert and key")
			caCert, caKey, err := retrieveIssuerCert()
			Expect(err).NotTo(HaveOccurred(), "Failed to retrieve issuer cert and key")

			By("creating the initial client certificate")
			clientCertPEM, clientKeyPEM, err := utils.GenerateClientCert("curl-est", caCert, caKey)
			Expect(err).NotTo(HaveOccurred(), "Failed to generate client cert")

			By("creating the CSR for the client certificate")
			// Workaround: for the SelfSigned signer, the key must be stored in a secret
			// and the CSR must have the experimental.cert-manager.io/private-key-secret-name annotation
			csrBytes, keyPEM, err := utils.GenerateCSR("curl-est")
			Expect(err).NotTo(HaveOccurred(), "Failed to generate CSR")

			By("creating the CSR secret")
			cmd = exec.Command("kubectl", "create", "secret", "generic", "dummy-key", "-n", namespace, "--from-literal", "tls.key="+string(keyPEM))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create CSR secret")

			By("making a /simpleenroll request")
			clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
			Expect(err).NotTo(HaveOccurred(), "Failed to create client cert")
			caPool := x509.NewCertPool()
			caPool.AddCert(caCert)
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{clientCert},
						RootCAs:      caPool,
					},
				},
			}
			enroll := func() error {
				req, err := http.NewRequest("POST", "https://localhost:4443/.well-known/est/simpleenroll", bytes.NewReader(csrBytes))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/pkcs10")
				resp, err := client.Do(req)
				if err != nil {
					return err
				}

				patchCSR(namespace)

				defer resp.Body.Close() //nolint:errcheck
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
				}
				return nil
			}
			Eventually(enroll, 1*time.Minute).Should(Succeed(), "Failed to enroll client certificate")

			By("making a /simplereenroll request")
			reenroll := func(csrBytes []byte) error {
				req, err := http.NewRequest("POST", "https://localhost:4443/.well-known/est/simplereenroll", bytes.NewReader(csrBytes))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/pkcs10")
				resp, err := client.Do(req)
				if err != nil {
					return err
				}

				patchCSR(namespace)
				defer resp.Body.Close() //nolint:errcheck
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
				}
				return nil
			}
			// The first reenroll should give us the enrolled certificate
			Expect(reenroll(csrBytes)).To(Succeed(), "Failed to reenroll client certificate")

			By("creating a rekeyed CSR")
			csrBytes, keyPEM, err = utils.GenerateCSR("curl-est")
			Expect(err).NotTo(HaveOccurred(), "Failed to generate CSR")

			By("deleting the old CSR secret")
			cmd = exec.Command("kubectl", "delete", "--ignore-not-found=true", "secret", "dummy-key", "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete old CSR secret")

			By("creating the rekeyed CSR secret")
			cmd = exec.Command("kubectl", "create", "secret", "generic", "dummy-key", "-n", namespace, "--from-literal", "tls.key="+string(keyPEM))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create rekeyed CSR secret")

			By("making a /simplereenroll request with the rekeyed CSR")
			Eventually(reenroll, 1*time.Minute).WithArguments(csrBytes).Should(Succeed(), "Failed to reenroll client certificate with rekeyed CSR")
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=cert-estuary-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			curlCommand := fmt.Sprintf(`"curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"`, token, metricsServiceName, namespace)
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--labels", "app.kubernetes.io/name=curl",
				"--overrides",
				utils.GetCurlPodSpec(curlCommand, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			Eventually(verifyCurlUp, 5*time.Minute).WithArguments("curl-metrics", namespace).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

func verifyCurlUp(g Gomega, name, namespace string) {
	cmd := exec.Command("kubectl", "get", "pods", name,
		"-o", "jsonpath={.status.phase}",
		"-n", namespace)
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
}

func getESTOutput(name, namespace string, expected, unexpected []string) string {
	By("getting the curl-est logs")
	cmd := exec.Command("kubectl", "logs", name, "-n", namespace)
	estOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	for _, str := range expected {
		Expect(estOutput).To(ContainSubstring(str))
	}
	for _, str := range unexpected {
		Expect(estOutput).NotTo(ContainSubstring(str))
	}
	return estOutput
}

func retrieveIssuerCert() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cmd := exec.Command("kubectl", "get", "secret", "-n", namespace, "est-selfsigned-ca", "-o", `jsonpath={.data.tls\.crt}`)
	out, err := utils.Run(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve issuer cert: %w", err)
	}
	// Decode the base64 encoded cert
	certPEM, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(out)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode issuer cert: %w", err)
	}
	cmd = exec.Command("kubectl", "get", "secret", "-n", namespace, "est-selfsigned-ca", "-o", `jsonpath={.data.tls\.key}`)
	out, err = utils.Run(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve issuer key: %w", err)
	}
	// Decode the base64 encoded key
	keyPEM, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(out)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode issuer key: %w", err)
	}
	certDER, _ := pem.Decode(certPEM)
	if certDER == nil {
		return nil, nil, fmt.Errorf("failed to decode issuer cert PEM: %s", certPEM)
	}
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, nil, fmt.Errorf("failed to decode issuer key PEM: %s", keyPEM)
	}
	caCert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse issuer cert: %w, DER: %s", err, certDER)
	}
	caKey, err := x509.ParseECPrivateKey(keyDER.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse issuer key: %w, DER: %s", err, keyDER)
	}
	return caCert, caKey, nil
}

// workaround: for the SelfSigned signer, patch the CSR with the secret name
func patchCSR(namespace string) {
	cmd := exec.Command("kubectl", "get", "csr", "-n", namespace, "-l", "cert-estuary.atelierhsn.com/estauthorizedclient=estauthorizedclient-sample", "-o", "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to get CSR name")
	names := strings.Split(output, "\n")
	for _, name := range names {
		if name == "" {
			continue
		}
		cmd = exec.Command("kubectl", "patch", "csr", name, "-n", namespace,
			"-p", `{"metadata":{"annotations":{"experimental.cert-manager.io/private-key-secret-name":"dummy-key"}}}`,
			"--type=merge")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to patch CSR with secret name")
		// approve the CSR
		cmd = exec.Command("kubectl", "certificate", "approve", name, "-n", namespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to approve CSR")
	}
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
