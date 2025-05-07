Simple Worker to issue Cloudflare TURN Credential

```json
->
GET /api/credentials/generate for credential

<-
{
  "username": "xxx",
  "credential": "yyy",
  "ttl": $CREDENTIAL_TTL
}
```

| env      | Description | default |
| ----------- | ----------- | ----------- |
| KV | KV namespace | - |
| ACCOUNT_TAG | Cloudflare account id | - |
| ANALYTICS_TOKEN | Account - Account Analytics - read | - |
| CREDENTIAL_TTL | max 48h (172800s) | 86400 |
| EGRESS_LIMIT | Cloudflare to client data transfer | 700 |
| TURN_KEY_ID | - | - |
| TURN_KEY_SECRET | - | - |
| IPV4_CREDENTIAL_GENERATE_RATE_LIMITER | for /32 IPv4 | not set, but necessary |
| IPV6_CREDENTIAL_GENERATE_RATE_LIMITER | for /64 IPv6 | not set, but necessary |

credit to Claude 3.7 Sonnet