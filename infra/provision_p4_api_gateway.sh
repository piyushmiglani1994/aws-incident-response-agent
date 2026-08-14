#!/bin/bash
# provision_p4_api_gateway.sh
# Pattern 4: ALB → Security Inspection Layer → VPC Interface Endpoint → API Gateway (private)
# Deploys a private REST API Gateway behind a VPC Interface Endpoint
# Path routing: /p4/* → VPC Endpoint → API Gateway
# Creates CloudWatch alarms with p4- prefix for incident response testing
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
API_NAME="incident-demo-p4-api"
ENDPOINT_SG_NAME="incident-demo-p4-endpoint-sg"
TG_NAME="incident-demo-p4-tg"
PATH_PATTERN="/p4/*"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P4: ALB → Security Layer → VPC Endpoint → API Gateway"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Fetch ALB details ──────────────────────────────────────────────────────────
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

SUBNETS=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].AvailabilityZones[*].SubnetId' \
  --output text --region $REGION | tr '\t' ' ')

ALB_SG=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].SecurityGroups[0]' \
  --output text --region $REGION)

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[0].ListenerArn' \
  --output text --region $REGION)

echo "  VPC: $VPC_ID"

# ── VPC Endpoint Security Group ───────────────────────────────────────────────
echo ""
echo "── Creating VPC Endpoint Security Group ──"
ENDPOINT_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=$ENDPOINT_SG_NAME Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$ENDPOINT_SG" = "None" ] || [ -z "$ENDPOINT_SG" ]; then
  ENDPOINT_SG=$(aws ec2 create-security-group \
    --group-name $ENDPOINT_SG_NAME \
    --description "VPC Endpoint SG for P4 API Gateway demo" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text --region $REGION)
fi
aws ec2 authorize-security-group-ingress \
  --group-id $ENDPOINT_SG --protocol tcp --port 443 \
  --source-group $ALB_SG --region $REGION 2>/dev/null || true
echo "  Endpoint SG: $ENDPOINT_SG ✓"

# ── VPC Interface Endpoint for API Gateway ────────────────────────────────────
echo ""
echo "── Creating VPC Interface Endpoint (execute-api) ──"
ENDPOINT_ID=$(aws ec2 describe-vpc-endpoints \
  --filters Name=service-name,Values=com.amazonaws.$REGION.execute-api \
            Name=vpc-id,Values=$VPC_ID \
            Name=vpc-endpoint-state,Values=available,pending \
  --query 'VpcEndpoints[0].VpcEndpointId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$ENDPOINT_ID" = "None" ] || [ -z "$ENDPOINT_ID" ]; then
  ENDPOINT_ID=$(aws ec2 create-vpc-endpoint \
    --vpc-id $VPC_ID \
    --service-name com.amazonaws.$REGION.execute-api \
    --vpc-endpoint-type Interface \
    --subnet-ids $SUBNETS \
    --security-group-ids $ENDPOINT_SG \
    --query 'VpcEndpoint.VpcEndpointId' --output text --region $REGION)
  echo "  Created endpoint: $ENDPOINT_ID"
  echo "  Waiting for endpoint to become available..."
  aws ec2 wait vpc-endpoint-available --vpc-endpoint-ids $ENDPOINT_ID --region $REGION 2>/dev/null || sleep 30
else
  echo "  Existing endpoint: $ENDPOINT_ID"
fi

# ── Private API Gateway ───────────────────────────────────────────────────────
echo ""
echo "── Creating Private API Gateway ──"
RESOURCE_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "execute-api:Invoke",
    "Resource": "execute-api:/*",
    "Condition": {
      "StringEquals": {
        "aws:sourceVpce": "$ENDPOINT_ID"
      }
    }
  }]
}
POLICY
)

API_ID=$(aws apigateway get-rest-apis \
  --query "items[?name=='$API_NAME'].id" \
  --output text --region $REGION 2>/dev/null || echo "")

if [ -z "$API_ID" ] || [ "$API_ID" = "None" ]; then
  API_ID=$(aws apigateway create-rest-api \
    --name $API_NAME \
    --endpoint-configuration types=PRIVATE,vpcEndpointIds=$ENDPOINT_ID \
    --policy "$RESOURCE_POLICY" \
    --query 'id' --output text --region $REGION)
  echo "  API created: $API_ID"

  # Add a /p4 resource and GET method returning 200
  ROOT_ID=$(aws apigateway get-resources \
    --rest-api-id $API_ID \
    --query 'items[?path==`/`].id' \
    --output text --region $REGION)

  RESOURCE_ID=$(aws apigateway create-resource \
    --rest-api-id $API_ID \
    --parent-id $ROOT_ID \
    --path-part "p4" \
    --query 'id' --output text --region $REGION)

  aws apigateway put-method \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --authorization-type NONE \
    --region $REGION > /dev/null

  aws apigateway put-integration \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --type MOCK \
    --request-templates '{"application/json": "{\"statusCode\": 200}"}' \
    --region $REGION > /dev/null

  aws apigateway put-integration-response \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --status-code 200 \
    --region $REGION > /dev/null

  aws apigateway put-method-response \
    --rest-api-id $API_ID \
    --resource-id $RESOURCE_ID \
    --http-method GET \
    --status-code 200 \
    --region $REGION > /dev/null

  aws apigateway create-deployment \
    --rest-api-id $API_ID \
    --stage-name demo \
    --region $REGION > /dev/null

  echo "  Deployed to stage: demo"
else
  echo "  API exists: $API_ID"
fi

# ── CloudWatch Alarms (p4- prefix) ────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms (p4- prefix) ──"

aws cloudwatch put-metric-alarm \
  --alarm-name "p4-apigw-5xx-errors" \
  --alarm-description "P4: API Gateway 5xx error rate elevated" \
  --metric-name 5XXError \
  --namespace AWS/ApiGateway \
  --dimensions Name=ApiName,Value=$API_NAME Name=Stage,Value=demo \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --treat-missing-data notBreaching \
  --region $REGION

aws cloudwatch put-metric-alarm \
  --alarm-name "p4-apigw-no-requests" \
  --alarm-description "P4: API Gateway receiving no requests (endpoint may be broken)" \
  --metric-name Count \
  --namespace AWS/ApiGateway \
  --dimensions Name=ApiName,Value=$API_NAME Name=Stage,Value=demo \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --region $REGION

echo "  Alarm: p4-apigw-5xx-errors ✓"
echo "  Alarm: p4-apigw-no-requests ✓"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P4 setup complete"
echo "  API Gateway ID:  $API_ID"
echo "  VPC Endpoint:    $ENDPOINT_ID"
echo "  Endpoint SG:     $ENDPOINT_SG"
echo "  Alarms:          p4-apigw-5xx-errors, p4-apigw-no-requests"
echo ""
echo "  Trigger scenarios:"
echo "  • Delete VPC endpoint: aws ec2 delete-vpc-endpoints \\"
echo "      --vpc-endpoint-ids $ENDPOINT_ID --region $REGION"
echo "  • Delete API stage:    aws apigateway delete-stage \\"
echo "      --rest-api-id $API_ID --stage-name demo --region $REGION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
