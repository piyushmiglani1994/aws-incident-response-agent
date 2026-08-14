# Pattern 3 — ALB → Security Inspection Layer → NLB → Internal ALB → ECS Fargate

## Traffic flow

```
Internet → Public ALB → Security Inspection Layer (inline) → NLB → Internal ALB → ECS Fargate
```

## Alarm prefix: `p3-`

| Alarm name | Metric | Threshold |
|------------|--------|-----------|
| `p3-ecs-no-healthy-hosts` | Internal ALB HealthyHostCount | < 1 for 2 periods |

## What the agent investigates

1. **Security/inspection layer** — instance state, SG, route tables
2. **NLB** — listener state, target (internal ALB) health
3. **Internal ALB** — existence, listener state, SG rules
4. **ECS service** — `desiredCount` vs `runningCount`
5. **ECS tasks** — `lastStatus`, exit codes, container logs
6. **CloudTrail (last 2h)** — `UpdateService`, `DeleteLoadBalancer`, `RevokeSecurityGroupIngress`

## Failure scenarios

| Scenario | How to trigger | CloudTrail event |
|----------|---------------|-----------------|
| ECS scaled to 0 | `aws ecs update-service --desired-count 0` | `UpdateService` |
| Internal ALB deleted | `aws elbv2 delete-load-balancer --load-balancer-arn <arn>` | `DeleteLoadBalancer` |
| Internal ALB SG revoked | Remove inbound rule on internal ALB SG | `RevokeSecurityGroupIngress` |
| Internal ALB listener deleted | `aws elbv2 delete-listener --listener-arn <arn>` | `DeleteListener` |
| ECS SG revoked | Remove inbound rule blocking internal ALB → container | `RevokeSecurityGroupIngress` |

## Provisioning script

```bash
bash infra/provision_p3_nlb_alb_ecs.sh
```
