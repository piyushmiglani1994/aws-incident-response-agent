# Pattern 2 — ALB → Security Inspection Layer → NLB → ECS Fargate

## Traffic flow

```
Internet → Public ALB → Security Inspection Layer (inline) → NLB → ECS Fargate
```

## Alarm prefix: `p2-`

| Alarm name | Metric | Threshold |
|------------|--------|-----------|
| `p2-ecs-no-healthy-hosts` | ALB HealthyHostCount | < 1 for 2 periods |

## What the agent investigates

1. **Security/inspection layer** — instance state, SG, route tables
2. **NLB** — listener state, target group health, SG rules
3. **ECS service** — `desiredCount` vs `runningCount`
4. **ECS tasks** — `lastStatus`, `stopCode`, container exit codes
5. **Container image** — pull errors (`CannotPullContainerError`)
6. **CloudTrail (last 2h)** — `UpdateService`, `RevokeSecurityGroupIngress`, `DeleteListener`

## Failure scenarios

| Scenario | How to trigger | CloudTrail event |
|----------|---------------|-----------------|
| Scale to 0 | `aws ecs update-service --desired-count 0` | `UpdateService` |
| ECS SG revoked (CLI) | `aws ec2 revoke-security-group-ingress ...` | `RevokeSecurityGroupIngress` |
| ECS SG revoked (Console) | Remove inbound rule via AWS Console | `RevokeSecurityGroupIngress` |
| Bad image tag | Deploy non-existent image tag | No CloudTrail — agent checks `CannotPullContainerError` |
| NLB listener deleted | `aws elbv2 delete-listener --listener-arn <arn>` | `DeleteListener` |

## Provisioning script

```bash
bash infra/provision_ecs_app.sh
```
