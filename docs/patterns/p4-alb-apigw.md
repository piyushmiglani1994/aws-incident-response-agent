# Pattern 4 — ALB → Security Inspection Layer → VPC Endpoint → API Gateway (Private)

## Traffic flow

```
Internet → Public ALB → Security Inspection Layer (inline) → VPC Interface Endpoint → Private API Gateway
```

## Alarm prefix: `p4-`

| Alarm name | Metric | Threshold |
|------------|--------|-----------|
| `p4-apigw-5xx-errors` | API Gateway 5XXError | ≥ 5 in 1 period |
| `p4-apigw-no-requests` | API Gateway Count | < 1 in 5 minutes |

## What the agent investigates

1. **Security/inspection layer** — instance state, SG, route tables
2. **VPC Interface Endpoint** — state (available/pending/failed), subnet, SG
3. **API Gateway** — stage deployment status, custom domain mapping
4. **Endpoint SG** — inbound rule allowing HTTPS (443) from upstream
5. **CloudTrail (last 2h)** — `DeleteVpcEndpoint`, `DeleteStage`, `DeleteRestApi`

## Failure scenarios

| Scenario | How to trigger | CloudTrail event |
|----------|---------------|-----------------|
| VPC endpoint deleted | `aws ec2 delete-vpc-endpoints --vpc-endpoint-ids <id>` | `DeleteVpcEndpoint` |
| API stage deleted | `aws apigateway delete-stage --rest-api-id <id> --stage-name demo` | `DeleteStage` |
| Endpoint SG revoked | Remove HTTPS inbound from upstream SG | `RevokeSecurityGroupIngress` |
| API deleted | `aws apigateway delete-rest-api --rest-api-id <id>` | `DeleteRestApi` |

## Provisioning script

```bash
bash infra/provision_p4_api_gateway.sh
```
