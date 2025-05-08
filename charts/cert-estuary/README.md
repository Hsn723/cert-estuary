# cert-estuary Helm Chart

## Quick start

### Add the Helm repository

```sh
helm repo add cert-estuary https://hsn723.github.io/cert-estuary
helm repo update
```

### Install the chart

```sh
helm install --create-namespace --namespace cert-estuary cert-estuary cert-estuary/cert-estuary
```

Specify parameters using `--set key=value[,key=value]` arguments to `helm install`, or provide your own `values.yaml`:

```sh
helm install --create-namespace --namespace cert-estuary cert-estuary -f values.yaml cert-estuary/cert-estuary
```

## Values
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.repository | string | `"ghcr.io/hsn723/cert-estuary"` | Image repository to use |
| image.tag | string | `{{ .Chart.AppVersion }}` | Image tag to use |
| image.pullPolicy | string | "Always" | Image pullPolicy |
| controller.replicas | int | `2` | Number of controller Pod replicas |
| controller.resources | object | `{"requests":{"cpu":500m,"memory":"100Mi"}}` | Resources requested for controller Pod |
| controller.terminationGracePeriodSeconds | int | `10` | terminationGracePeriodSeconds for the controller Pod |
| controller.extraArgs | list | `["--leader-elect"]` | Additional arguments for the controller |
| issuerName | string | `""` | Specify the name of the Issuer for the EST server certificate. The EST server requires TLS and a self-signed issuer will be created if not set |

## Generate Manifests
```sh
helm template --namespace cert-estuary cert-estuary [-f values.yaml] cert-estuary/cert-estuary
```
