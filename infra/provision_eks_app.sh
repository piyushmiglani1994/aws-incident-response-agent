#!/bin/bash
# provision_eks_app.sh
# Creates EKS cluster, deploys nginx, registers behind incident-agent-alb
# Path routing: /eks/* → EKS target group
# ─────────────────────────────────────────────────────────────────────────────
# Prerequisites: eksctl installed in CloudShell
#   curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_Linux_amd64.tar.gz"
#   tar -xzf eksctl_Linux_amd64.tar.gz && sudo mv eksctl /usr/local/bin/
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
CLUSTER_NAME="incident-demo-eks"
NODE_GROUP="incident-demo-ng"
TG_NAME="incident-demo-eks-tg"
NAMESPACE="default"
APP_NAME="incident-demo-nginx"
NODE_PORT=30080
PATH_PATTERN="/eks/*"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Provisioning EKS App behind ALB"
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

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[?Port==`80`].ListenerArn | [0]' \
  --output text --region $REGION)

# Get subnets — need private subnets for EKS nodes
SUBNETS=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].AvailabilityZones[*].SubnetId' \
  --output text --region $REGION | tr '\t' ',')

SNS_ARN=$(aws cloudwatch describe-alarms \
  --alarm-names "incident-agent-UnhealthyHosts" \
  --query 'MetricAlarms[0].AlarmActions[0]' \
  --output text --region $REGION)

echo "  VPC: $VPC_ID | ALB SG: $ALB_SG"

# ── Install eksctl if not present ─────────────────────────────────────────────
if ! command -v eksctl &>/dev/null; then
  echo ""
  echo "── Installing eksctl ──"
  curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_Linux_amd64.tar.gz"
  tar -xzf eksctl_Linux_amd64.tar.gz
  sudo mv eksctl /usr/local/bin/
  rm -f eksctl_Linux_amd64.tar.gz
  echo "  ✓ eksctl installed: $(eksctl version)"
fi

# ── Create EKS Cluster ────────────────────────────────────────────────────────
CLUSTER_EXISTS=$(aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query 'cluster.status' \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ "$CLUSTER_EXISTS" != "ACTIVE" ]]; then
  echo ""
  echo "── Creating EKS cluster (takes ~15 min) ──"
  SUBNET_LIST=$(echo $SUBNETS | tr ',' ' ')

  eksctl create cluster \
    --name $CLUSTER_NAME \
    --region $REGION \
    --vpc-id $VPC_ID \
    --nodegroup-name $NODE_GROUP \
    --node-type t3.medium \
    --nodes 2 \
    --nodes-min 1 \
    --nodes-max 3 \
    --managed \
    --asg-access \
    --alb-ingress-access \
    --with-oidc

  echo "  ✓ EKS cluster created: $CLUSTER_NAME"
else
  echo "  ✓ EKS cluster already exists: $CLUSTER_NAME ($CLUSTER_EXISTS)"
fi

# ── Configure kubectl ─────────────────────────────────────────────────────────
echo ""
echo "── Configuring kubectl ──"
aws eks update-kubeconfig \
  --name $CLUSTER_NAME \
  --region $REGION
echo "  ✓ kubeconfig updated"

# ── Deploy nginx to EKS ───────────────────────────────────────────────────────
echo ""
echo "── Deploying nginx to EKS ──"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $APP_NAME
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
spec:
  replicas: 2
  selector:
    matchLabels:
      app: $APP_NAME
  template:
    metadata:
      labels:
        app: $APP_NAME
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 10
          periodSeconds: 15
---
apiVersion: v1
kind: Service
metadata:
  name: $APP_NAME-svc
  namespace: $NAMESPACE
spec:
  type: NodePort
  selector:
    app: $APP_NAME
  ports:
  - port: 80
    targetPort: 80
    nodePort: $NODE_PORT
YAML

echo "  ✓ Deployment and NodePort Service created"

# ── Wait for pods to be ready ─────────────────────────────────────────────────
echo ""
echo "── Waiting for pods to be ready ──"
kubectl rollout status deployment/$APP_NAME --timeout=120s
echo "  ✓ Pods running"

# ── Get EKS node instance IDs ─────────────────────────────────────────────────
echo ""
echo "── Fetching EKS node instance IDs ──"
NODE_IDS=$(aws ec2 describe-instances \
  --filters \
    "Name=tag:eks:cluster-name,Values=$CLUSTER_NAME" \
    "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text --region $REGION | tr '\t' ' ')
echo "  Node IDs: $NODE_IDS"

# ── Allow ALB → EKS node SG on NodePort ──────────────────────────────────────
echo ""
echo "── Allowing ALB traffic to EKS nodes on port $NODE_PORT ──"
EKS_NODE_SG=$(aws ec2 describe-instances \
  --instance-ids $(echo $NODE_IDS | awk '{print $1}') \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
  --output text --region $REGION)

aws ec2 authorize-security-group-ingress \
  --group-id $EKS_NODE_SG \
  --protocol tcp \
  --port $NODE_PORT \
  --source-group $ALB_SG \
  --region $REGION 2>/dev/null || echo "  (Rule already exists)"
echo "  ✓ SG rule added: ALB → EKS nodes port $NODE_PORT"

# ── Create ALB Target Group (instance type, NodePort) ─────────────────────────
echo ""
echo "── Creating ALB target group (instance type) ──"
TG_ARN=$(aws elbv2 describe-target-groups \
  --names $TG_NAME \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ -z "$TG_ARN" || "$TG_ARN" == "None" ]]; then
  TG_ARN=$(aws elbv2 create-target-group \
    --name $TG_NAME \
    --protocol HTTP \
    --port $NODE_PORT \
    --vpc-id $VPC_ID \
    --target-type instance \
    --health-check-path "/" \
    --health-check-port "$NODE_PORT" \
    --health-check-interval-seconds 30 \
    --healthy-threshold-count 2 \
    --unhealthy-threshold-count 3 \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text --region $REGION)
fi
echo "  ✓ TG: $TG_ARN"

# ── Register EKS nodes as targets ────────────────────────────────────────────
echo ""
echo "── Registering EKS nodes as ALB targets ──"
TARGETS=$(for id in $NODE_IDS; do echo "{\"Id\":\"$id\",\"Port\":$NODE_PORT}"; done | jq -s .)
aws elbv2 register-targets \
  --target-group-arn $TG_ARN \
  --targets $TARGETS \
  --region $REGION
echo "  ✓ Nodes registered: $NODE_IDS"

# ── Add ALB Listener Rule ─────────────────────────────────────────────────────
echo ""
echo "── Adding ALB listener rule for /eks/* ──"
RULE_EXISTS=$(aws elbv2 describe-rules \
  --listener-arn $LISTENER_ARN \
  --query "Rules[?Conditions[?Values[?contains(@, '/eks')]]].[RuleArn]" \
  --output text --region $REGION 2>/dev/null || echo "")

if [[ -z "$RULE_EXISTS" || "$RULE_EXISTS" == "None" ]]; then
  aws elbv2 create-rule \
    --listener-arn $LISTENER_ARN \
    --priority 20 \
    --conditions '[{"Field":"path-pattern","Values":["/eks/*"]}]' \
    --actions "[{\"Type\":\"forward\",\"TargetGroupArn\":\"$TG_ARN\"}]" \
    --region $REGION > /dev/null
  echo "  ✓ Listener rule: /eks/* → $TG_NAME"
fi

# ── CloudWatch Alarms ─────────────────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms ──"
TG_SUFFIX=$(echo $TG_ARN | awk -F':targetgroup/' '{print "targetgroup/"$2}')
ALB_ARN_FULL=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text --region $REGION)
ALB_SUFFIX=$(echo $ALB_ARN_FULL | awk -F':loadbalancer/' '{print $2}')

aws cloudwatch put-metric-alarm \
  --alarm-name "p2-incident-demo-eks-unhealthy" \
  --alarm-description "EKS app behind ALB has unhealthy targets" \
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
echo "  ✓ p2-incident-demo-eks-unhealthy"

aws cloudwatch put-metric-alarm \
  --alarm-name "p2-incident-demo-eks-no-healthy" \
  --alarm-description "EKS app — zero healthy targets" \
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
echo "  ✓ p2-incident-demo-eks-no-healthy"

# ── Summary ───────────────────────────────────────────────────────────────────
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].DNSName' --output text --region $REGION)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ EKS app provisioned"
echo ""
echo "  EKS Cluster:   $CLUSTER_NAME"
echo "  Deployment:    $APP_NAME (2 replicas)"
echo "  NodePort:      $NODE_PORT"
echo "  Target Group:  $TG_NAME"
echo "  ALB Rule:      /eks/* → EKS nginx"
echo "  Node SG:       $EKS_NODE_SG"
echo ""
echo "  Test: curl http://$ALB_DNS/eks/"
echo ""
echo "  Alarms (prefix p2- for Pattern 2 routing):"
echo "    p2-incident-demo-eks-unhealthy"
echo "    p2-incident-demo-eks-no-healthy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
