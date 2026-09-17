# eShield-Q Gateway — API Schemas

Pydantic models and enums describing the eShield-Q Gateway REST API. This is the
API contract: request and response shapes, field defaults, allowed values and
validators.

```bash
pip install eshieldq-gateway-schemas
```

Most callers want [`eshieldq-gateway-client`](https://github.com/qemcorp/eshieldq-gateway-client),
which wraps the API and depends on this package. Use these models directly when
you are building against the API yourself and want the request/response types.

Version **4.1.21**. See [SECURITY.md](SECURITY.md) to report a vulnerability.

© Quantum eMotion Corp. See [LICENSE.md](LICENSE.md).
