# NovaPay Platform

Enterprise payment processing platform built on AWS. Handles card tokenization,
transaction signing, merchant authentication, and document management for
financial institutions.

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │           AWS us-east-1                  │
                    │                                          │
Internet ──→ CloudFront (CDN) ──→ ALB (TLS 1.2/1.3)          │
                    │                   │                       │
                    │            ┌──────┴──────┐               │
                    │            │  ECS Tasks  │               │
                    │     ┌──────┤ auth-svc    │               │
                    │     │      │ payment-svc │               │
                    │     │      │ document-svc│               │
                    │     │      └─────────────┘               │
                    │     │                                     │
                    │  Lambda ← EventBridge (scheduled)        │
                    │  (webhook-processor, token-validator,     │
                    │   key-rotation-scheduler)                │
                    │                                          │
                    │  KMS (RSA-4096 + ECC P-384 keys)         │
                    │  ACM (RSA-2048 certificates)             │
                    │  Aurora PostgreSQL (encrypted at rest)   │
                    └──────────────────────────────────────────┘
```

## Services

| Service | Language | Purpose |
|---|---|---|
| `auth-service` | Python 3.11 | JWT issuance (RS256), OAuth 2.0 / PKCE, mTLS |
| `payment-service` | Python 3.11 | Card encryption (RSA-OAEP), transaction signing (ECDSA) |
| `document-service` | Python 3.11 | Document signing (RSA-PSS), contract management |
| `api-gateway` | Python 3.11 (Lambda) | Webhook verification, token validation |

## Cryptographic Dependencies

| Component | Algorithm | Key Size | Purpose |
|---|---|---|---|
| JWT signing | RSA | 4096-bit | Access/refresh tokens |
| Card encryption | RSA-OAEP | 4096-bit | PAN/CVV transit encryption |
| Transaction signing | ECDSA | P-256 | Per-transaction audit records |
| Document signing | RSA-PSS | 4096-bit | Merchant agreements |
| Client auth | ECDSA | P-256 / P-384 | OAuth client assertions |
| KMS token key | RSA | 4096-bit | Webhook delivery signatures |
| KMS document key | ECC | P-384 | High-value contract co-signing |
| TLS termination | ECDHE-RSA | 2048-bit | ALB + CloudFront |
| ACM certificates | RSA | 2048-bit | api.novapay.io, assets.novapay.io |

## Development

```bash
# Start all services locally
docker compose up

# Run tests
cd services/auth-service && pytest -v
cd services/payment-service && pytest -v

# Terraform plan (requires AWS credentials)
cd terraform && terraform plan -var="environment=dev"
```

## Security

Cryptographic primitives are under active PQC migration review.
See [SECURITY.md](SECURITY.md) and [NOVA-4821](https://jira.novapay.io/browse/NOVA-4821)
for the post-quantum readiness roadmap.
