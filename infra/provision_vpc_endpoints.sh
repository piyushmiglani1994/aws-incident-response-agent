#!/bin/bash
# provision_vpc_endpoints.sh
# Creates VPC endpoints so ECS Fargate tasks work without public IPs
# Also pushes nginx to ECR (no Docker Hub dependency)
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
VPC_ID="${VPC_ID}"
SUBNETS="${SUBNET_IDS}"
ALB_SG="${ALB_SG_ID}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CLUSTER_NAME="incident-demo-cluster"
SERVICE_NAME="incident-demo-ecs-app"
TASK_FAMILY="incident-demo-nginx"
ECR_REPO="incident-demo-nginx"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VPC Endpoints + ECR Setup for ECS Fargate"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Account: $ACCOUNT_ID | VPC: $VPC_ID"

# ── Security Group for VPC Endpoints ─────────────────────────────────────────
echo ""
echo "── Creating VPC endpoint security group ──"
ENDPOINT_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=incident-demo-endpoint-sg Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION 2>/dev/null)

if [[ -z "$ENDPOINT_SG" || "$ENDPOINT_SG" == "None" ]]; then
  ENDPOINT_SG=$(aws ec2 create-security-group \
    --group-name incident-demo-endpoint-sg \
    --description "SG for VPC interface endpoints" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text --region $REGION)

  # Allow HTTPS from within VPC (ECS tasks need to reach endpoints on 443)
  aws ec2 authorize-security-group-ingress \
    --group-id $ENDPOINT_SG \
    --protocol tcp \
    --port 443 \
    --cidr $(aws ec2 describe-vpcs --vpc-ids $VPC_ID \
      --query 'Vpcs[0].CidrBlock' --output text --region $REGION) \
    --region $REGION
fi
echo "  Endpoint SG: $ENDPOINT_SG"

# ── Get route table for S3 gateway endpoint ───────────────────────────────────
ROUTE_TABLE_IDS=$(aws ec2 describe-route-tables \
  --filters Name=vpc-id,Values=$VPC_ID \
  --query 'RouteTables[*].RouteTableId' \
  --output text --region $REGION | tr '\t' ' ')

SUBNET_ARRAY=($SUBNETS)

# ── Helper: create endpoint if not exists ─────────────────────────────────────
create_interface_endpoint() {
  local SERVICE=$1
  local NAME=$2

  EXISTING=$(aws ec2 describe-vpc-endpoints \
    --filters \
      Name=vpc-id,Values=$VPC_ID \
      Name=service-name,Values=$SERVICE \
      Name=vpc-endpoint-state,Values=available,pending \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text --region $REGION 2>/dev/null)

  if [[ -z "$EXISTING" || "$EXISTING" == "None" ]]; then
    EP_ID=$(aws ec2 create-vpc-endpoint \
      --vpc-id $VPC_ID \
      --service-name $SERVICE \
      --vpc-endpoint-type Interface \
      --subnet-ids ${SUBNET_ARRAY[@]} \
      --security-group-ids $ENDPOINT_SG \
      --private-dns-enabled \
      --query 'VpcEndpoint.VpcEndpointId' \
      --output text --region $REGION)
    echo "  ✓ Created $NAME: $EP_ID"
  else
    echo "  ✓ $NAME already exists: $EXISTING"
  fi
}

create_gateway_endpoint() {
  local SERVICE=$1
  local NAME=$2

  EXISTING=$(aws ec2 describe-vpc-endpoints \
    --filters \
      Name=vpc-id,Values=$VPC_ID \
      Name=service-name,Values=$SERVICE \
      Name=vpc-endpoint-state,Values=available \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text --region $REGION 2>/dev/null)

  if [[ -z "$EXISTING" || "$EXISTING" == "None" ]]; then
    EP_ID=$(aws ec2 create-vpc-endpoint \
      --vpc-id $VPC_ID \
      --service-name $SERVICE \
      --vpc-endpoint-type Gateway \
      --route-table-ids $ROUTE_TABLE_IDS \
      --query 'VpcEndpoint.VpcEndpointId' \
      --output text --region $REGION)
    echo "  ✓ Created $NAME: $EP_ID"
  else
    echo "  ✓ $NAME already exists: $EXISTING"
  fi
}

# ── Create VPC Endpoints ──────────────────────────────────────────────────────
echo ""
echo "── Creating VPC endpoints ──"
create_interface_endpoint "com.amazonaws.$REGION.logs"       "CloudWatch Logs"
create_interface_endpoint "com.amazonaws.$REGION.ecr.api"   "ECR API"
create_interface_endpoint "com.amazonaws.$REGION.ecr.dkr"   "ECR DKR"
create_gateway_endpoint   "com.amazonaws.$REGION.s3"         "S3 Gateway"

echo ""
echo "  Waiting 30s for endpoints to become available..."
sleep 30

# ── Allow ECS task SG → endpoint SG on 443 ───────────────────────────────────
ECS_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=incident-demo-ecs-sg Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION)

aws ec2 authorize-security-group-egress \
  --group-id $ECS_SG \
  --protocol tcp \
  --port 443 \
  --destination-group $ENDPOINT_SG \
  --region $REGION 2>/dev/null || true
echo "  ✓ ECS tasks can reach VPC endpoints on 443"

# ── Push nginx to ECR ─────────────────────────────────────────────────────────
echo ""
echo "── Pushing nginx:alpine to ECR ──"

# Create ECR repo if not exists
aws ecr describe-repositories --repository-names $ECR_REPO --region $REGION \
  > /dev/null 2>/dev/null || \
  aws ecr create-repository --repository-name $ECR_REPO --region $REGION > /dev/null
echo "  ✓ ECR repo: $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO"

# Login, pull, tag, push
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin \
  $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

docker pull nginx:alpine --quiet
ECR_IMAGE="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest"
docker tag nginx:alpine $ECR_IMAGE
docker push $ECR_IMAGE --quiet
echo "  ✓ Pushed: $ECR_IMAGE"

# ── Update task definition to use ECR image ───────────────────────────────────
echo ""
echo "── Updating task definition to use ECR image ──"

EXEC_ROLE_ARN=$(aws iam get-role \
  --role-name ecsTaskExecutionRole \
  --query 'Role.Arn' --output text)

aws ecs register-task-definition \
  --family $TASK_FAMILY \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 \
  --memory 512 \
  --execution-role-arn $EXEC_ROLE_ARN \
  --container-definitions "[
    {
      \"name\": \"nginx\",
      \"image\": \"$ECR_IMAGE\",
      \"portMappings\": [{\"containerPort\": 80, \"protocol\": \"tcp\"}],
      \"essential\": true,
      \"logConfiguration\": {
        \"logDriver\": \"awslogs\",
        \"options\": {
          \"awslogs-group\": \"/ecs/$SERVICE_NAME\",
          \"awslogs-region\": \"$REGION\",
          \"awslogs-stream-prefix\": \"ecs\",
          \"awslogs-create-group\": \"true\"
        }
      }
    }
  ]" \
  --region $REGION \
  --query 'taskDefinition.{family:family,revision:revision}' > /dev/null
echo "  ✓ Task def updated: image = ECR (no Docker Hub)"

# ── Update ECS service — no public IP needed now ──────────────────────────────
echo ""
echo "── Redeploying ECS service (assignPublicIp=DISABLED) ──"
aws ecs update-service \
  --cluster $CLUSTER_NAME \
  --service $SERVICE_NAME \
  --task-definition $TASK_FAMILY \
  --network-configuration "awsvpcConfiguration={
    subnets=[$(echo $SUBNETS | tr ' ' ',')],
    securityGroups=[$ECS_SG],
    assignPublicIp=DISABLED
  }" \
  --force-new-deployment \
  --region $REGION \
  --query 'service.{desired:desiredCount,running:runningCount}' > /dev/null
echo "  ✓ Service redeployed — no public IP, using VPC endpoints"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ VPC endpoints created. Traffic flow:"
echo ""
echo "  ECS Task (private IP)"
echo "    → CloudWatch Logs  via com.amazonaws.$REGION.logs endpoint"
echo "    → ECR image pull   via com.amazonaws.$REGION.ecr.api/dkr endpoints"
echo "    → S3 (ECR layers)  via S3 gateway endpoint"
echo "    → No internet access required ✓"
echo ""
echo "  Waiting for ECS task to start (~2 min)..."
echo "  Check: aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME"
echo "         --query 'services[0].{desired:desiredCount,running:runningCount}'"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
