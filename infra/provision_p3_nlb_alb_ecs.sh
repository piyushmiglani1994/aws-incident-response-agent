#!/bin/bash
# provision_p3_nlb_alb_ecs.sh
# Pattern 3: ALB → Security Inspection Layer → NLB → Internal ALB → ECS Fargate
# Deploys an ECS Fargate service behind an internal ALB, fronted by an NLB
# Path routing: /p3/* → NLB → Internal ALB → ECS
# Creates CloudWatch alarms with p3- prefix for incident response testing
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
NLB_NAME="incident-demo-p3-nlb"
INT_ALB_NAME="incident-demo-p3-int-alb"
CLUSTER_NAME="incident-demo-cluster"
SERVICE_NAME="incident-demo-p3-app"
TASK_FAMILY="incident-demo-p3-nginx"
ECS_SG_NAME="incident-demo-p3-ecs-sg"
INT_ALB_SG_NAME="incident-demo-p3-int-alb-sg"
TG_NAME_ECS="incident-demo-p3-ecs-tg"
TG_NAME_NLB="incident-demo-p3-nlb-tg"
CONTAINER_PORT=80
PATH_PATTERN="/p3/*"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P3: ALB → Security Layer → NLB → Internal ALB → ECS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Fetch public ALB details ───────────────────────────────────────────────────
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
  --output text --region $REGION | tr '\t' ',')

ALB_SG=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].SecurityGroups[0]' \
  --output text --region $REGION)

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[0].ListenerArn' \
  --output text --region $REGION)

echo "  VPC: $VPC_ID | Subnets: $SUBNETS"

# ── Internal ALB Security Group ───────────────────────────────────────────────
echo ""
echo "── Creating Internal ALB Security Group ──"
INT_ALB_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=$INT_ALB_SG_NAME Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$INT_ALB_SG" = "None" ] || [ -z "$INT_ALB_SG" ]; then
  INT_ALB_SG=$(aws ec2 create-security-group \
    --group-name $INT_ALB_SG_NAME \
    --description "Internal ALB SG for P3 demo" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text --region $REGION)
fi
aws ec2 authorize-security-group-ingress \
  --group-id $INT_ALB_SG --protocol tcp --port 80 \
  --cidr 10.0.0.0/8 --region $REGION 2>/dev/null || true
echo "  Internal ALB SG: $INT_ALB_SG ✓"

# ── ECS Security Group ────────────────────────────────────────────────────────
echo ""
echo "── Creating ECS Security Group ──"
ECS_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=$ECS_SG_NAME Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$ECS_SG" = "None" ] || [ -z "$ECS_SG" ]; then
  ECS_SG=$(aws ec2 create-security-group \
    --group-name $ECS_SG_NAME \
    --description "ECS SG for P3 demo" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text --region $REGION)
fi
aws ec2 authorize-security-group-ingress \
  --group-id $ECS_SG --protocol tcp --port 80 \
  --source-group $INT_ALB_SG --region $REGION 2>/dev/null || true
echo "  ECS SG: $ECS_SG ✓"

# ── Internal ALB ──────────────────────────────────────────────────────────────
echo ""
echo "── Creating Internal ALB ──"
SUBNET_JSON=$(echo $SUBNETS | tr ',' '\n' | jq -R . | jq -s .)
INT_ALB_ARN=$(aws elbv2 create-load-balancer \
  --name $INT_ALB_NAME \
  --scheme internal \
  --type application \
  --subnets $(echo $SUBNETS | tr ',' ' ') \
  --security-groups $INT_ALB_SG \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-load-balancers --names $INT_ALB_NAME \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text --region $REGION)
echo "  Internal ALB: $INT_ALB_ARN"

# ── ECS Target Group (for internal ALB) ───────────────────────────────────────
ECS_TG_ARN=$(aws elbv2 create-target-group \
  --name $TG_NAME_ECS \
  --protocol HTTP --port 80 \
  --vpc-id $VPC_ID \
  --target-type ip \
  --health-check-path "/p3/" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-target-groups --names $TG_NAME_ECS \
    --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)

# Internal ALB listener
aws elbv2 create-listener \
  --load-balancer-arn $INT_ALB_ARN \
  --protocol HTTP --port 80 \
  --default-actions Type=forward,TargetGroupArn=$ECS_TG_ARN \
  --region $REGION 2>/dev/null || true
echo "  Internal ALB listener → ECS TG ✓"

# ── NLB ───────────────────────────────────────────────────────────────────────
echo ""
echo "── Creating NLB ──"
INT_ALB_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns $INT_ALB_ARN \
  --query 'LoadBalancers[0].DNSName' --output text --region $REGION)

NLB_ARN=$(aws elbv2 create-load-balancer \
  --name $NLB_NAME \
  --scheme internal \
  --type network \
  --subnets $(echo $SUBNETS | tr ',' ' ') \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-load-balancers --names $NLB_NAME \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text --region $REGION)

NLB_TG_ARN=$(aws elbv2 create-target-group \
  --name $TG_NAME_NLB \
  --protocol TCP --port 80 \
  --vpc-id $VPC_ID \
  --target-type alb \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-target-groups --names $TG_NAME_NLB \
    --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)

aws elbv2 register-targets \
  --target-group-arn $NLB_TG_ARN \
  --targets Id=$INT_ALB_ARN \
  --region $REGION 2>/dev/null || true

aws elbv2 create-listener \
  --load-balancer-arn $NLB_ARN \
  --protocol TCP --port 80 \
  --default-actions Type=forward,TargetGroupArn=$NLB_TG_ARN \
  --region $REGION 2>/dev/null || true
echo "  NLB: $NLB_ARN ✓"

# ── ECS Task + Service ────────────────────────────────────────────────────────
echo ""
echo "── Registering ECS Task Definition ──"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws ecs register-task-definition \
  --family $TASK_FAMILY \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 256 --memory 512 \
  --container-definitions "[{
    \"name\": \"nginx\",
    \"image\": \"nginx:alpine\",
    \"portMappings\": [{\"containerPort\": $CONTAINER_PORT}],
    \"essential\": true
  }]" \
  --region $REGION > /dev/null

echo "── Creating ECS Service ──"
aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $REGION 2>/dev/null || true

aws ecs create-service \
  --cluster $CLUSTER_NAME \
  --service-name $SERVICE_NAME \
  --task-definition $TASK_FAMILY \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$ECS_SG],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=$ECS_TG_ARN,containerName=nginx,containerPort=$CONTAINER_PORT" \
  --region $REGION 2>/dev/null || true
echo "  ECS service $SERVICE_NAME ✓"

# ── Public ALB → NLB rule ─────────────────────────────────────────────────────
echo ""
echo "── Adding public ALB rule → NLB ──"
NLB_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns $NLB_ARN \
  --query 'LoadBalancers[0].DNSName' --output text --region $REGION)

NLB_TG_FOR_ALB=$(aws elbv2 create-target-group \
  --name "incident-demo-p3-pub-tg" \
  --protocol HTTP --port 80 \
  --vpc-id $VPC_ID \
  --target-type ip \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-target-groups --names "incident-demo-p3-pub-tg" \
    --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)

PRIORITY=$(( RANDOM % 400 + 200 ))
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority $PRIORITY \
  --conditions Field=path-pattern,Values="$PATH_PATTERN" \
  --actions Type=forward,TargetGroupArn=$NLB_TG_FOR_ALB \
  --region $REGION 2>/dev/null || true
echo "  Path $PATH_PATTERN → NLB ✓"

# ── CloudWatch Alarms (p3- prefix) ────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms (p3- prefix) ──"
ECS_TG_SUFFIX=$(echo $ECS_TG_ARN | awk -F':' '{print $NF}')
INT_ALB_SUFFIX=$(echo $INT_ALB_ARN | awk -F':' '{print $NF}')

aws cloudwatch put-metric-alarm \
  --alarm-name "p3-ecs-no-healthy-hosts" \
  --alarm-description "P3: No healthy ECS hosts on internal ALB" \
  --metric-name HealthyHostCount \
  --namespace AWS/ApplicationELB \
  --dimensions Name=TargetGroup,Value=$ECS_TG_SUFFIX Name=LoadBalancer,Value=$INT_ALB_SUFFIX \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 1 \
  --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --region $REGION

echo "  Alarm: p3-ecs-no-healthy-hosts ✓"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P3 setup complete"
echo "  NLB DNS:      $NLB_DNS"
echo "  Int ALB DNS:  $INT_ALB_DNS"
echo "  Alarm:        p3-ecs-no-healthy-hosts"
echo ""
echo "  Trigger scenario:"
echo "  aws ecs update-service --cluster $CLUSTER_NAME \\"
echo "    --service $SERVICE_NAME --desired-count 0 --region $REGION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
