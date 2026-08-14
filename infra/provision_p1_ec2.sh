#!/bin/bash
# provision_p1_ec2.sh
# Pattern 1: ALB → Security Inspection Layer → EC2
# Deploys a simple Apache EC2 instance behind the incident-agent-alb
# Path routing: /p1/* → EC2 target group
# Creates CloudWatch alarms with p1- prefix for incident response testing
# ─────────────────────────────────────────────────────────────────────────────
set -e

REGION="us-east-1"
ALB_NAME="incident-agent-alb"
TG_NAME="incident-demo-p1-ec2-tg"
SG_NAME="incident-demo-p1-ec2-sg"
PATH_PATTERN="/p1/*"
INSTANCE_TYPE="t3.micro"
AMI_ID="ami-0c02fb55956c7d316"   # Amazon Linux 2 (us-east-1) — update for your region

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P1: ALB → Security Layer → EC2"
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
  --output text --region $REGION | tr '\t' ',')

ALB_SG=$(aws elbv2 describe-load-balancers \
  --names $ALB_NAME \
  --query 'LoadBalancers[0].SecurityGroups[0]' \
  --output text --region $REGION)

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query 'Listeners[0].ListenerArn' \
  --output text --region $REGION)

echo "  VPC:      $VPC_ID"
echo "  ALB SG:   $ALB_SG"
echo "  Subnets:  $SUBNETS"

# ── Security Group for EC2 ─────────────────────────────────────────────────────
echo ""
echo "── Creating EC2 Security Group ──"
EC2_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=$SG_NAME Name=vpc-id,Values=$VPC_ID \
  --query 'SecurityGroups[0].GroupId' --output text --region $REGION 2>/dev/null || echo "None")

if [ "$EC2_SG" = "None" ] || [ -z "$EC2_SG" ]; then
  EC2_SG=$(aws ec2 create-security-group \
    --group-name $SG_NAME \
    --description "EC2 SG for P1 incident response demo" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text --region $REGION)
  echo "  Created: $EC2_SG"
else
  echo "  Exists:  $EC2_SG"
fi

# Allow HTTP from ALB SG
aws ec2 authorize-security-group-ingress \
  --group-id $EC2_SG \
  --protocol tcp --port 80 \
  --source-group $ALB_SG \
  --region $REGION 2>/dev/null || true

echo "  Inbound rule: port 80 from ALB SG ✓"

# ── IAM Instance Profile (SSM access) ─────────────────────────────────────────
echo ""
echo "── Ensuring SSM instance profile ──"
aws iam create-role \
  --role-name incident-demo-ec2-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  --region $REGION 2>/dev/null || true

aws iam attach-role-policy \
  --role-name incident-demo-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true

aws iam create-instance-profile \
  --instance-profile-name incident-demo-ec2-profile \
  --region $REGION 2>/dev/null || true

aws iam add-role-to-instance-profile \
  --instance-profile-name incident-demo-ec2-profile \
  --role-name incident-demo-ec2-role 2>/dev/null || true

sleep 5  # propagation delay

# ── Launch EC2 Instance ────────────────────────────────────────────────────────
echo ""
echo "── Launching EC2 instance ──"
SUBNET_1=$(echo $SUBNETS | cut -d',' -f1)

INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type $INSTANCE_TYPE \
  --security-group-ids $EC2_SG \
  --subnet-id $SUBNET_1 \
  --iam-instance-profile Name=incident-demo-ec2-profile \
  --user-data '#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo "<h1>P1 Demo - EC2</h1>" > /var/www/html/index.html
mkdir -p /var/www/html/p1
echo "<h1>P1 Demo - EC2 App</h1>" > /var/www/html/p1/index.html' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=incident-demo-p1-ec2}]" \
  --query 'Instances[0].InstanceId' --output text --region $REGION)

echo "  Instance: $INSTANCE_ID"
echo "  Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region $REGION

INSTANCE_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text --region $REGION)
echo "  Private IP: $INSTANCE_IP"

# ── Target Group ──────────────────────────────────────────────────────────────
echo ""
echo "── Creating Target Group ──"
TG_ARN=$(aws elbv2 create-target-group \
  --name $TG_NAME \
  --protocol HTTP --port 80 \
  --vpc-id $VPC_ID \
  --health-check-path "/p1/" \
  --health-check-interval-seconds 30 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text --region $REGION 2>/dev/null || \
  aws elbv2 describe-target-groups --names $TG_NAME \
    --query 'TargetGroups[0].TargetGroupArn' --output text --region $REGION)

echo "  TG: $TG_ARN"

# Register EC2
aws elbv2 register-targets \
  --target-group-arn $TG_ARN \
  --targets Id=$INSTANCE_ID \
  --region $REGION

echo "  Registered EC2 instance ✓"

# ── ALB Listener Rule ─────────────────────────────────────────────────────────
echo ""
echo "── Adding ALB listener rule ──"
PRIORITY=$(( RANDOM % 400 + 100 ))
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority $PRIORITY \
  --conditions Field=path-pattern,Values="$PATH_PATTERN" \
  --actions Type=forward,TargetGroupArn=$TG_ARN \
  --region $REGION 2>/dev/null || echo "  Rule may already exist — skipping"

echo "  Path $PATH_PATTERN → EC2 TG ✓"

# ── CloudWatch Alarms (p1- prefix) ────────────────────────────────────────────
echo ""
echo "── Creating CloudWatch alarms (p1- prefix) ──"

TG_SUFFIX=$(echo $TG_ARN | awk -F':' '{print $NF}')
ALB_SUFFIX=$(echo $ALB_ARN | awk -F':' '{print $NF}')

aws cloudwatch put-metric-alarm \
  --alarm-name "p1-ec2-no-healthy-hosts" \
  --alarm-description "P1: No healthy EC2 hosts behind ALB" \
  --metric-name HealthyHostCount \
  --namespace AWS/ApplicationELB \
  --dimensions Name=TargetGroup,Value=$TG_SUFFIX Name=LoadBalancer,Value=$ALB_SUFFIX \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 1 \
  --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --region $REGION

echo "  Alarm: p1-ec2-no-healthy-hosts ✓"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  P1 setup complete"
echo "  Instance:  $INSTANCE_ID ($INSTANCE_IP)"
echo "  Test URL:  http://<ALB-DNS>/p1/"
echo "  Alarm:     p1-ec2-no-healthy-hosts"
echo ""
echo "  Trigger scenarios:"
echo "  • Stop httpd:  aws ssm send-command --instance-ids $INSTANCE_ID \\"
echo "      --document-name AWS-RunShellScript \\"
echo "      --parameters commands=['systemctl stop httpd']"
echo "  • Revoke SG:   aws ec2 revoke-security-group-ingress \\"
echo "      --group-id $EC2_SG --protocol tcp --port 80 \\"
echo "      --source-group $ALB_SG --region $REGION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
