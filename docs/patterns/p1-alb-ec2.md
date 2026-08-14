# Pattern 1 — ALB → Security Inspection Layer → EC2

## Traffic flow

```
Internet → Public ALB → Security Inspection Layer (inline) → EC2 Instance
```

## Alarm prefix: `p1-`

| Alarm name | Metric | Threshold |
|------------|--------|-----------|
| `p1-ec2-no-healthy-hosts` | ALB HealthyHostCount | < 1 for 2 periods |

## What the agent investigates

1. **Security/inspection layer** — EC2 instance state, SG inbound rules, route tables
2. **EC2 instance** — running/stopped/terminated state
3. **EC2 Security Group** — inbound rule on port 80/443 from ALB SG
4. **SSM command history** — recent `send-command` invocations (e.g. `systemctl stop httpd`)
5. **Application health** — CPU, memory, disk via CloudWatch agent metrics
6. **CloudTrail (last 2h)** — `StopInstances`, `RevokeSecurityGroupIngress`, `SendCommand`

## Failure scenarios

| Scenario | How to trigger | CloudTrail event |
|----------|---------------|-----------------|
| App stopped via SSM | `aws ssm send-command --document-name AWS-RunShellScript --parameters commands=['systemctl stop httpd']` | `SendCommand` |
| SG inbound rule revoked | `aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port 80 --source-group <alb-sg>` | `RevokeSecurityGroupIngress` |
| Instance stopped | `aws ec2 stop-instances --instance-ids <id>` | `StopInstances` |
| OOM / process crash | Generate memory pressure inside EC2 | No CloudTrail event — agent checks exit codes / metrics |

## Provisioning script

```bash
bash infra/provision_p1_ec2.sh
```
