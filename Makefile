PROJECT_NAME = cert-estuary
# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/hsn723/$(PROJECT_NAME):dev
export IMG

CERT_MANAGER_VERSION ?= v1.16.3
KIND_CLUSTER ?= $(PROJECT_NAME)
export KIND_CLUSTER

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

KIND_CONFIG = test/e2e/kind-config.yaml

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: kustomize controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd:allowDangerousTypes=true webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	$(KUSTOMIZE) build config/helm/overlays/crds > charts/$(PROJECT_NAME)/templates/generated/crds/$(PROJECT_NAME).atelierhsn.com_estauthorizedclients.yaml
	# $(KUSTOMIZE) build config/helm/overlays/templates > charts/$(PROJECT_NAME)/templates/generated/generated.yaml
	if [ -f VERSION ]; then \
		sed -i "s/\(appVersion: \)[0-9]\+\.[0-9]\+\.[0-9]\+/\1$$(cat VERSION)/" charts/$(PROJECT_NAME)/Chart.yaml; \
	fi

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
.PHONY: test-e2e
test-e2e:
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@$(KIND) get clusters | grep -q '$(KIND_CLUSTER)' || { \
		echo "No Kind cluster is running. Please start a Kind cluster before running the e2e tests."; \
		exit 1; \
	}
	env PATH="$(LOCALBIN)::$$PATH" \
		go test ./test/e2e/ -v -ginkgo.v

.PHONY: start-kind
start-kind:
	$(KIND) create cluster --name=$(KIND_CLUSTER) --config=$(KIND_CONFIG) --image=kindest/node:v$(KIND_NODE_TAG) --wait 1m

.PHONY: stop-kind
stop-kind:
	$(KIND) delete cluster --name=$(KIND_CLUSTER)
	-docker image rm $(IMG)
	-docker image prune -f

.PHONY: start-e2e
start-e2e: kind kubectl start-kind

.PHONY: lint
lint:
	if [ -z "$(shell which pre-commit)" ]; then pip3 install pre-commit; fi
	pre-commit install
	pre-commit run --all-files

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	CGO_ENABLED=0 go build -o $(PROJECT_NAME) -ldflags="-w -s" cmd/cert-estuary/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/cert-estuary/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: build ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name $(PROJECT_NAME)-builder
	$(CONTAINER_TOOL) buildx use $(PROJECT_NAME)-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm $(PROJECT_NAME)-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
HELM ?=  $(LOCALBIN)/helm
KUBECTL ?= $(LOCALBIN)/kubectl
KIND ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
CONTAINER_STRUCTURE_TEST = $(LOCALBIN)/container-structure-test
YQ ?= $(LOCALBIN)/yq

KUBERNETES_VERSION = $(shell curl -L -s https://dl.k8s.io/release/stable.txt)
KIND_NODE_TAG = ""


## Tool Versions
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.17.2
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
GOLANGCI_LINT_VERSION ?= v1.63.4
HELM_VERSION ?= 3.17.0

.PHONY: kubectl
kubectl: $(KUBECTL) ## Download kubectl locally if necessary.
$(KUBECTL): $(LOCALBIN)
	curl -sfL -o $@ https://dl.k8s.io/release/$(KUBERNETES_VERSION)/bin/linux/amd64/kubectl
	chmod a+x $@

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(KIND): $(LOCALBIN)
	curl -sfL -o $@ https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-linux-amd64
	chmod a+x $@

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(HELM): $(BINDIR)
	curl -L -sS https://get.helm.sh/helm-v$(HELM_VERSION)-linux-amd64.tar.gz \
	  | tar xz -C $(BINDIR) --strip-components 1 linux-amd64/helm

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: container-structure-test
container-structure-test: $(CONTAINER_STRUCTURE_TEST) # Download container-structure-test locally if necessary.
$(CONTAINER_STRUCTURE_TEST): $(LOCALBIN)
	curl -sSLf -o $(CONTAINER_STRUCTURE_TEST) https://github.com/GoogleContainerTools/container-structure-test/releases/latest/download/container-structure-test-linux-amd64 && chmod +x $(CONTAINER_STRUCTURE_TEST)

.PHONY: container-structure-test
container-structure-test: container-structure-test yq
	$(YQ) '.builds[0] | .goarch[]' .goreleaser.yml | xargs -I {} $(CONTAINER_STRUCTURE_TEST) test --image ghcr.io/hsn723/$(PROJECT_NAME):$(shell git describe --tags --abbrev=0 --match "v*" || echo v0.0.0)-next-{} --platform linux/{} --config cst.yaml

.PHONY: yq
yq: $(YQ) ## Download yq locally if necessary.
$(YQ): $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install github.com/mikefarah/yq/v4@latest

.PHONY: get-k8s-versions
get-k8s-versions:
	@LATEST_VERSION=$$(curl -L -s https://dl.k8s.io/release/stable.txt) && \
	KIND_TAGS=$$(gh api /repos/kubernetes-sigs/kind/releases/latest | jq -r '.body' | grep -Po '(?<=- v)(?:\d+\.\d+\.\d+: `kindest\/node:v)\K(\d+\.\d+\.\d+@sha256:[a-f0-9]+)') && \
	LATEST_VERSION_MAJOR=$$(echo $${LATEST_VERSION} | grep -Po '(?<=v)\d+\.\d+') && \
	LATEST_KIND_TAG=$$(printf "%s\n" $${KIND_TAGS} | grep "$${LATEST_VERSION_MAJOR}" | sort -u | tail -n 1) && \
	PREVIOUS_VERSION_MAJOR=$$(echo $${LATEST_VERSION_MAJOR} | awk -F. -v OFS=. '{$$NF -= 1; print}') && \
	PREVIOUS_KIND_TAG=$$(printf "%s\n" $${KIND_TAGS} | grep "$${PREVIOUS_VERSION_MAJOR}" | sort -u | tail -n 1) && \
	PREVIOUS2_VERSION_MAJOR=$$(echo $${PREVIOUS_VERSION_MAJOR} | awk -F. -v OFS=. '{$$NF -= 1; print}') && \
	PREVIOUS2_KIND_TAG=$$(printf "%s\n" $${KIND_TAGS} | grep "$${PREVIOUS2_VERSION_MAJOR}" | sort -u | tail -n 1) && \
	echo "['$${PREVIOUS2_KIND_TAG}', '$${PREVIOUS_KIND_TAG}', '$${LATEST_KIND_TAG}']"
