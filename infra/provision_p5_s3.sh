#!/bin/bash
# provision_p5_s3.sh
# Pattern 5: ALB → Security Inspection Layer → VPC Gateway Endpoint → S3 Static Website
# Deploys an S3 static website accessible only via a VPC Gateway Endpoint
# Path routing: /p5/* → VPC Gateway Endpoint → S3 Bucket
# Creates CloudWatch alarms with p5- prefix for incident response testing
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
BUCKET_NAME="incident-demo-p5-static-$(aws sts get-caller-identity --query Account --output text)"
TG_NAME="incident-demo-p5-tg"
PATH_PATTERN="/p5/*"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P5: ALB → Security Layer → VPC Endpoint → S3 Static Site"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Fetch ALB/VPC details ──────────────────────────────────────────────────────
echo ""
echo "── Fetching ALB details ──"
ALB_ARN=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text --region $REGION)

VPC_ID=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].VpcId' \
  --output text --region $REGION)

# Get route table IDs for the VPC
ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query 'RouteTables[*].RouteTableId' \
  --output text --region $REGION | tr '\t' ' ')

echo "  VPC: $VPC_ID"
echo "  Route tables: $ROUTE_TABLE_IDS"

# ── S3 VPC Gateway Endpoint ───────────────────────────────────────────────────
echo ""
echo "── Creating S3 VPC Gateway Endpoint ──"
ENDPOINT_ID=$(aws ec2 describe-vpc-endpoints \
  --filters Name=service-name,Values=com.amazonaws.$REGION.s3 \
            Name=vpc-id,Values=$VPC_ID \
            Name=vpc-endpoint-type,Values=Gateway \
            Name=vpc-endpoint-state,Values=available,pending \
  --query 'VpcEndpoints[0].VpcEndpointId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$ENDPOINT_ID" = "None" ] || [ -z "$ENDPOINT_ID" ]; then
  ENDPOINT_ID=$(aws ec2 create-vpc-endpoint \
    --vpc-id $VPC_ID \
    --service-name com.amazonaws.$REGION.s3 \
    --vpc-endpoint-type Gateway \
    --route-table-ids $ROUTE_TABLE_IDS \
    --query 'VpcEndpoint.VpcEndpointId' --output text --region $REGION)
  echo "  Created S3 Gateway Endpoint: $ENDPOINT_ID"
else
  echo "  Existing S3 Gateway Endpoint: $ENDPOINT_ID"
fi

# ── S3 Bucket + Static Website ────────────────────────────────────────────────
echo ""
echo "── Creating S3 bucket and static website ──"

# Create bucket
aws s3api create-bucket \
  --bucket $BUCKET_NAME \
  --region $REGION 2>/dev/null || echo "  Bucket already exists"

# Block public access (only VPC endpoint can access)
aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false \
  --region $REGION

# Enable static website hosting
aws s3api put-bucket-website \
  --bucket $BUCKET_NAME \
  --website-configuration '{
    "IndexDocument": {"Suffix": "index.html"},
    "ErrorDocument": {"Key": "error.html"}
  }' \
  --region $REGION

# Bucket policy — allow access only from VPC endpoint
aws s3api put-bucket-policy \
  --bucket $BUCKET_NAME \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": \"*\",
      \"Action\": \"s3:GetObject\",
      \"Resource\": \"arn:aws:s3:::$BUCKET_NAME/*\",
      \"Condition\": {
        \"StringEquals\": {
          \"aws:sourceVpce\": \"$ENDPOINT_ID\"
        }
      }
    }]
  }" \
  --region $REGION

# Upload sample HTML
cat > /tmp/index.html <<'HTML'
<!DOCTYPE html>
<html>
<head><title>P5 Demo - S3 Static Site</title></head>
<body>
  <h1>Pattern 5: S3 Static Website</h1>
  <p>Served via VPC Gateway Endpoint — no public internet access.</p>
</body>
</html>
HTML

aws s3 cp /tmp/index.html s3://$BUCKET_NAME/index.html --region $REGION
aws s3 cp /tmp/index.html s3://$BUCKET_NAME/p5/index.html --region $REGION
echo "  Bucket: $BUCKET_NAME ✓"
echo "  Static website enabled ✓"
echo "  VPC-only bucket policy applied ✓"

# ── CloudWatch Alarms (p5- prefix) ────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms (p5- prefix) ──"

aws cloudwatch put-metric-alarm \
  --alarm-name "p5-s3-4xx-errors" \
  --alarm-description "P5: S3 bucket returning 4xx errors (policy or content issue)" \
  --metric-name 4xxErrors \
  --namespace AWS/S3 \
  --dimensions Name=BucketName,Value=$BUCKET_NAME Name=FilterId,Value=EntireBucket \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 10 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --region $REGION

aws cloudwatch put-metric-alarm \
  --alarm-name "p5-s3-5xx-errors" \
  --alarm-description "P5: S3 bucket returning 5xx errors" \
  --metric-name 5xxErrors \
  --namespace AWS/S3 \
  --dimensions Name=BucketName,Value=$BUCKET_NAME Name=FilterId,Value=EntireBucket \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --region $REGION

# Enable S3 request metrics (needed for above alarms)
aws s3api put-bucket-metrics-configuration \
  --bucket $BUCKET_NAME \
  --id EntireBucket \
  --metrics-configuration Id=EntireBucket \
  --region $REGION 2>/dev/null || true

echo "  Alarm: p5-s3-4xx-errors ✓"
echo "  Alarm: p5-s3-5xx-errors ✓"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P5 setup complete"
echo "  Bucket:       $BUCKET_NAME"
echo "  VPC Endpoint: $ENDPOINT_ID"
echo "  Website URL:  http://$BUCKET_NAME.s3-website-$REGION.amazonaws.com"
echo "  Alarms:       p5-s3-4xx-errors, p5-s3-5xx-errors"
echo ""
echo "  Trigger scenarios:"
echo "  • Delete bucket policy (breaks VPC endpoint access):"
echo "    aws s3api delete-bucket-policy --bucket $BUCKET_NAME --region $REGION"
echo "  • Delete VPC endpoint:"
echo "    aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $ENDPOINT_ID --region $REGION"
echo "  • Disable static website hosting:"
echo "    aws s3api delete-bucket-website --bucket $BUCKET_NAME --region $REGION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
