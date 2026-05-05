# ACME webhook for Active24 DNS API

This repository contains code and supporting files for an ACME webhook that
interacts with the [active24.cz](https://customer.active24.com/user/api) DNS
**v2 REST API**.

## Installation

### Requirements

- [cert-manager](https://cert-manager.io/docs/installation/)
- API key and secret for the Active24 REST API

The API uses HMAC-SHA1 signed HTTP Basic authentication. Create a secret
containing the API key and secret:

```
kubectl create secret generic active24-credentials --namespace cert-manager \
    --from-literal='apiUser=my-api-key' \
    --from-literal='apiSecret=my-api-secret'
```

Create a ClusterIssuer:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: admin@somegreatdomain.tld
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - selector:
        dnsZones:
          - somegreatdomain.tld
      dns01:
        webhook:
          groupName: acme.yourdomain.tld
          solverName: active24
          config:
            apiSecretRef:
              name: active24-credentials
              # namespace is optional; defaults to the resource namespace
              # namespace: cert-manager
            # optional overrides (defaults shown):
            # apiUserKey: apiUser
            # apiSecretKey: apiSecret
            # apiUrl: https://rest.active24.cz
            domain: somegreatdomain.tld
```

Replace `somegreatdomain.tld` with the actual domain managed by Active24.

Install using helm:

```
helm upgrade --install ac24 ./chart --namespace cert-manager
```

Create a certificate:

```yaml
kind: Certificate
apiVersion: cert-manager.io/v1
metadata:
  name: my-certificate
spec:
  commonName: somegreatdomain.tld
  dnsNames:
    - somegreatdomain.tld
    - '*.somegreatdomain.tld'
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-prod
  secretName: somegreatdomain.tld-tls
```

## Migrating from the legacy v1 API configuration

The previous configuration field `apiKeySecretRef` (single API key) has been
replaced by `apiSecretRef`, which points at a Secret containing two keys:
`apiUser` and `apiSecret`. The default base URL has changed from
`https://api.active24.com` to `https://rest.active24.cz`. The webhook resolves
the numeric Active24 service ID automatically from the configured `domain` using
the service list endpoint before calling the v2 DNS record API.
