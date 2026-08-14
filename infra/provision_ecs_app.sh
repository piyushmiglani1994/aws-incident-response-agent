#!/bin/bash
# provision_ecs_app.sh
# Deploys a simple nginx ECS Fargate app behind incident-agent-alb
# Path routing: /ecs/* → ECS target group
# Creates CloudWatch alarms for incident response testing
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
CLUSTER_NAME="incident-demo-cluster"
SERVICE_NAME="incident-demo-ecs-app"
TASK_FAMILY="incident-demo-nginx"
TG_NAME="incident-demo-ecs-tg"
CONTAINER_PORT=80
PATH_PATTERN="/ecs/*"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Provisioning ECS Fargate App behind ALB"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Fetch ALB details ─────────────────────────────────────────────────────────
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

ALB_SG=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].SecurityGroups[0]' \
  --output text --region $REGION)

# Get private subnets (reuse ALB subnets)
SUBNETS=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].AvailabilityZones[*].SubnetId' \
  --output text --region $REGION | tr '\t' ',')

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[?Port==`80`].ListenerArn | [0]' \
  --output text --region $REGION)

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "  VPC:      $VPC_ID"
echo "  ALB SG:   $ALB_SG"
echo "  Subnets:  $SUBNETS"
echo "  Listener: $LISTENER_ARN"

# ── SNS ARN for alarms ────────────────────────────────────────────────────────
SNS_ARN=$(aws cloudwatch describe-alarms \
  --alarm-names "incident-agent-UnhealthyHosts" \
  --query 'MetricAlarms[0].AlarmActions[0]' \
  --output text --region $REGION)
echo "  SNS ARN:  $SNS_ARN"

# ── Security Group for ECS tasks ──────────────────────────────────────────────
echo ""
echo "── Creating ECS task security group ──"
ECS_SG=$(aws ec2 create-security-group \
  --group-name incident-demo-ecs-sg \
  --description "SG for incident-demo ECS tasks" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text --region $REGION 2>/dev/null || \
  aws ec2 describe-security-groups \
    --filters Name=group-name,Values=incident-demo-ecs-sg Name=vpc-id,Values=$VPC_ID \
    --query 'SecurityGroups[0].GroupId' --output text --region $REGION)

# Allow inbound from ALB SG on port 80
aws ec2 authorize-security-group-ingress \
  --group-id $ECS_SG \
  --protocol tcp \
  --port 80 \
  --source-group $ALB_SG \
  --region $REGION 2>/dev/null || echo "  (SG rule already exists)"

echo "  ECS SG: $ECS_SG"

# ── IAM role for ECS task execution ──────────────────────────────────────────
echo ""
echo "── ECS task execution role ──"
EXEC_ROLE_ARN=$(aws iam get-role \
  --role-name ecsTaskExecutionRole \
  --query 'Role.Arn' --output text 2>/dev/null || echo "")

if [[ -z "$EXEC_ROLE_ARN" || "$EXEC_ROLE_ARN" == "None" ]]; then
  TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  EXEC_ROLE_ARN=$(aws iam create-role \
    --role-name ecsTaskExecutionRole \
    --assume-role-policy-document "$TRUST" \
    --query 'Role.Arn' --output text)
  aws iam attach-role-policy \
    --role-name ecsTaskExecutionRole \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
  echo "  Created ecsTaskExecutionRole"
  sleep 10
fi
echo "  Role: $EXEC_ROLE_ARN"

# ── ECS Cluster ───────────────────────────────────────────────────────────────
echo ""
echo "── Creating ECS cluster ──"
aws ecs create-cluster \
  --cluster-name $CLUSTER_NAME \
  --region $REGION > /dev/null 2>/dev/null || true
echo "  ✓ Cluster: $CLUSTER_NAME"

# ── Task Definition ───────────────────────────────────────────────────────────
echo ""
echo "── Registering task definition ──"
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
      \"image\": \"nginx:alpine\",
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
echo "  ✓ Task definition: $TASK_FAMILY"

# ── Target Group ──────────────────────────────────────────────────────────────
echo ""
echo "── Creating target group ──"
TG_ARN=$(aws elbv2 describe-target-groups \
  --names $TG_NAME \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ -z "$TG_ARN" || "$TG_ARN" == "None" ]]; then
  TG_ARN=$(aws elbv2 create-target-group \
    --name $TG_NAME \
    --protocol HTTP \
    --port 80 \
    --vpc-id $VPC_ID \
    --target-type ip \
    --health-check-path "/" \
    --health-check-interval-seconds 30 \
    --healthy-threshold-count 2 \
    --unhealthy-threshold-count 3 \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text --region $REGION)
  echo "  ✓ Created TG: $TG_ARN"
else
  echo "  ✓ Existing TG: $TG_ARN"
fi

# ── ALB Listener Rule ─────────────────────────────────────────────────────────
echo ""
echo "── Adding ALB listener rule for /ecs/* ──"
RULE_ARN=$(aws elbv2 describe-rules \
  --listener-arn $LISTENER_ARN \
  --query "Rules[?Conditions[?Values[?contains(@, '/ecs')]]].[RuleArn]" \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ -z "$RULE_ARN" || "$RULE_ARN" == "None" ]]; then
  aws elbv2 create-rule \
    --listener-arn $LISTENER_ARN \
    --priority 10 \
    --conditions '[{"Field":"path-pattern","Values":["/ecs/*"]}]' \
    --actions "[{\"Type\":\"forward\",\"TargetGroupArn\":\"$TG_ARN\"}]" \
    --region $REGION > /dev/null
  echo "  ✓ Listener rule created: /ecs/* → $TG_NAME"
else
  echo "  ✓ Listener rule already exists"
fi

# ── ECS Service ───────────────────────────────────────────────────────────────
echo ""
echo "── Creating ECS Fargate service ──"
SUBNET_JSON=$(echo $SUBNETS | tr ',' '\n' | jq -R . | jq -s .)
SVC_EXISTS=$(aws ecs describe-services \
  --cluster $CLUSTER_NAME \
  --services $SERVICE_NAME \
  --query 'services[?status==`ACTIVE`].serviceName | [0]' \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ -z "$SVC_EXISTS" || "$SVC_EXISTS" == "None" ]]; then
  aws ecs create-service \
    --cluster $CLUSTER_NAME \
    --service-name $SERVICE_NAME \
    --task-definition $TASK_FAMILY \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$ECS_SG],assignPublicIp=DISABLED}" \
    --load-balancers "targetGroupArn=$TG_ARN,containerName=nginx,containerPort=80" \
    --region $REGION \
    --query 'service.{name:serviceName,status:status}' > /dev/null
  echo "  ✓ Service created: $SERVICE_NAME"
else
  echo "  ✓ Service already running: $SERVICE_NAME"
fi

# ── CloudWatch Alarms ─────────────────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms ──"

TG_SUFFIX=$(echo $TG_ARN | awk -F':targetgroup/' '{print "targetgroup/"$2}')
ALB_SUFFIX=$(echo $ALB_ARN | awk -F':loadbalancer/' '{print $2}')

aws cloudwatch put-metric-alarm \
  --alarm-name "p2-incident-demo-ecs-unhealthy" \
  --alarm-description "ECS app behind ALB has unhealthy targets" \
  --namespace "AWS/ApplicationELB" \
  --metric-name "UnHealthyHostCount" \
  --dimensions \
      Name=TargetGroup,Value="$TG_SUFFIX" \
      Name=LoadBalancer,Value="$ALB_SUFFIX" \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$SNS_ARN" \
  --ok-actions "$SNS_ARN" \
  --region $REGION
echo "  ✓ p2-incident-demo-ecs-unhealthy"

aws cloudwatch put-metric-alarm \
  --alarm-name "p2-incident-demo-ecs-no-healthy" \
  --alarm-description "ECS app — zero healthy targets" \
  --namespace "AWS/ApplicationELB" \
  --metric-name "HealthyHostCount" \
  --dimensions \
      Name=TargetGroup,Value="$TG_SUFFIX" \
      Name=LoadBalancer,Value="$ALB_SUFFIX" \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 1 \
  --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --alarm-actions "$SNS_ARN" \
  --ok-actions "$SNS_ARN" \
  --region $REGION
echo "  ✓ p2-incident-demo-ecs-no-healthy"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ ECS app provisioned"
echo ""
echo "  Cluster:       $CLUSTER_NAME"
echo "  Service:       $SERVICE_NAME"
echo "  Target Group:  $TG_NAME"
echo "  ALB Rule:      /ecs/* → ECS nginx"
echo "  ECS SG:        $ECS_SG"
echo ""
echo "  Alarms created (prefix p2- for Pattern 2 routing):"
echo "    p2-incident-demo-ecs-unhealthy"
echo "    p2-incident-demo-ecs-no-healthy"
echo ""
echo "  Wait ~2 min for ECS task to start and register healthy."
echo "  Then test: curl http://<ALB_DNS>/ecs/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
