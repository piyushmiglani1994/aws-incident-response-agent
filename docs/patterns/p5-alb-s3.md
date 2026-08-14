# Pattern 5 — ALB → Security Inspection Layer → VPC Gateway Endpoint → S3 Static Website

## Traffic flow

```
Internet → Public ALB → Security Inspection Layer (inline) → VPC Gateway Endpoint → S3 Bucket (static website)
```

## Alarm prefix: `p5-`

| Alarm name | Metric | Threshold |
|------------|--------|-----------|
| `p5-s3-4xx-errors` | S3 4xxErrors | ≥ 10 in 5 minutes |
| `p5-s3-5xx-errors` | S3 5xxErrors | ≥ 5 in 5 minutes |

## What the agent investigates

1. **Security/inspection layer** — instance state, SG, route tables
2. **VPC Gateway Endpoint** — state, route table association
3. **S3 bucket** — existence, static website hosting enabled/disabled
4. **S3 bucket policy** — VPC endpoint condition present and correct
5. **CloudTrail (last 2h)** — `DeleteBucketWebsite`, `DeleteBucketPolicy`, `DeleteVpcEndpoint`, `DeleteBucket`

## Failure scenarios

| Scenario | How to trigger | CloudTrail event |
|----------|---------------|-----------------|
| Bucket policy deleted (blocks VPC endpoint) | `aws s3api delete-bucket-policy --bucket <name>` | `DeleteBucketPolicy` |
| Static website hosting disabled | `aws s3api delete-bucket-website --bucket <name>` | `DeleteBucketWebsite` |
| VPC Gateway Endpoint deleted | `aws ec2 delete-vpc-endpoints --vpc-endpoint-ids <id>` | `DeleteVpcEndpoint` |
| Bucket deleted | `aws s3 rb s3://<name> --force` | `DeleteBucket` |

## Provisioning script

```bash
bash infra/provision_p5_s3.sh
```
