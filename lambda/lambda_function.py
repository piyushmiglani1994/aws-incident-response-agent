import json
import os
import urllib.request
import urllib.error
import boto3
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Alarm type detection
# ---------------------------------------------------------------------------

def detect_alarm_type(alarm_name: str, metric_name: str) -> str:
    """
    Classify alarm into investigation type.

    Architecture patterns (detected by alarm name prefix):
      p1-*  → Public ALB → Palo Alto → EC2
      p2-*  → Public ALB → Palo Alto → Internal NLB → ECS/EKS
      p3-*  → Public ALB → Palo Alto → Internal NLB → Internal ALB → ECS/EKS
      p4-*  → Public ALB → Palo Alto → VPC Endpoint → API Gateway
      p5-*  → Public ALB → Palo Alto → VPC Endpoint → S3

    Name your alarms with these prefixes, e.g.:
      p1-prod-webserver-unhealthy
      p2-prod-ecs-service-down
    """
    name   = alarm_name.lower()
    metric = metric_name.lower()

    # Architecture pattern detection (highest priority)
    if name.startswith("p1-"):
        return "p1_alb_pa_ec2"
    if name.startswith("p2-"):
        return "p2_alb_pa_nlb_ecs"
    if name.startswith("p3-"):
        return "p3_alb_pa_nlb_alb_ecs"
    if name.startswith("p4-"):
        return "p4_alb_pa_apigw"
    if name.startswith("p5-"):
        return "p5_alb_pa_s3"

    # Metric-based detection (legacy / single-account)
    if "nohealthyhost" in name or ("healthyhost" in metric and "un" not in metric):
        return "no_healthy_host"
    if "unhealthyhost" in name or "unhealthyhost" in metric:
        return "unhealthy_host"
    if "rejected" in name or "rejectedconnection" in metric:
        return "rejected_conn"
    if "alb5xx" in name or "elb_5xx" in metric:
        return "alb_5xx"
    if "target5xx" in name or "target_5xx" in metric:
        return "target_5xx"
    if "statuscheck" in name or "statuscheck" in metric:
        return "status_check"
    if "ecstask" in name or "runningtaskcount" in metric:
        return "ecs_task"
    if "ecs" in name or "runningtask" in metric:
        return "ecs"
    if "rdscpu" in name or ("cpuutilization" in metric and "rds" in name):
        return "rds_cpu"
    if "rdsconn" in name or "databaseconnections" in metric:
        return "rds_connections"
    if "rdsstorage" in name or "freestoragespace" in metric:
        return "rds_storage"
    if "highcpu" in name or "cpuutilization" in metric:
        return "cpu"
    return "generic"


# ---------------------------------------------------------------------------
# Prompt builder — one per alarm type
# ---------------------------------------------------------------------------

def build_incident_message(alarm_name, account_id, region, timestamp,
                           reason, metric_ctx, alarm_type) -> str:

    metric_name  = metric_ctx["metric_name"]
    namespace    = metric_ctx["namespace"]
    threshold    = metric_ctx["threshold"]
    breach_value = metric_ctx["breach_value"]
    dimensions   = metric_ctx["dimensions"]

    dim_str       = ", ".join(f"{k}={v}" for k, v in dimensions.items()) or "N/A"
    threshold_str = f"{threshold:.1f}"    if threshold   is not None else "N/A"
    breach_str    = f"{breach_value:.1f}" if breach_value is not None else "N/A"

    # Compute time window — only look at events AFTER this time
    two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    header = f"""INCIDENT ALERT
==============
Alarm     : {alarm_name}
Account   : {account_id}
Region    : {region}
Time (UTC): {timestamp}
Metric    : {metric_name} ({namespace})
Resource  : {dim_str}
Threshold : {threshold_str}  |  Actual: {breach_str}
Trigger   : {reason}
Investigation window: {two_hours_ago} to now (ignore older events)
"""

    FORMAT_REMINDER = """
RULES:
- Only use events after {two_hours_ago} — older events are NOT the cause
- If SSM shows app service was stopped, that IS the root cause — stop there
- Do not speculate beyond what tool calls confirm

Respond in this format only:
PROBLEM: [1 sentence — exact cause with resource name]
EVIDENCE: [2-3 lines — timestamps, actor, action confirmed from tool calls]
FIX: [exact CLI command or numbered steps]
""".format(two_hours_ago=two_hours_ago)

    # ── CPU spike ────────────────────────────────────────────────────────────
    if alarm_type == "cpu":
        return header + f"""
Investigate in this order:
1. SSM list-command-invocations --filters key=InvokedAfter,value={two_hours_ago} --details
   → look for stress, load, or intensive commands run on the instance
2. CloudTrail lookup-events --start-time {two_hours_ago} for RunInstances, StartAutomation, UpdateService
3. CloudWatch CPUUtilization datapoints to confirm spike timing
""" + FORMAT_REMINDER

    # ── ALB unhealthy host ───────────────────────────────────────────────────
    if alarm_type == "unhealthy_host":
        return header + f"""
Investigate in this order — STOP as soon as you find the cause:
1. elbv2 describe-target-health for {dim_str} → get reason code (FailedHealthChecks / Timeout)
2. SSM list-command-invocations --filters key=InvokedAfter,value={two_hours_ago} --details
   → if a command stopped httpd/nginx/app, THAT IS THE ROOT CAUSE — report it
3. Only if SSM shows nothing: CloudTrail lookup-events --start-time {two_hours_ago}
   for RevokeSecurityGroupIngress — check if SG was changed AFTER {two_hours_ago}
4. Only if SG is the cause: ec2 describe-security-groups to confirm current rules
""" + FORMAT_REMINDER

    # ── No healthy hosts (service completely down) ───────────────────────────
    if alarm_type == "no_healthy_host":
        return header + f"""
CRITICAL — zero healthy targets. Investigate in this order — STOP at first confirmed cause:
1. elbv2 describe-target-health for {dim_str} → get exact reason codes
2. SSM list-command-invocations --filters key=InvokedAfter,value={two_hours_ago} --details
   → if a command stopped httpd/nginx/the app service, THAT IS THE ROOT CAUSE — report it
3. Only if SSM shows nothing: CloudTrail lookup-events --start-time {two_hours_ago}
   for RevokeSecurityGroupIngress, DeregisterTargets, DeleteListener
4. Only if SG/config is the cause: ec2 describe-security-groups to confirm
""" + FORMAT_REMINDER

    # ── Rejected connections ──────────────────────────────────────────────────
    if alarm_type == "rejected_conn":
        return header + f"""
Investigate in this order:
1. ec2 describe-security-groups for ALB SG — is port 80/443 open?
2. CloudTrail lookup-events --start-time {two_hours_ago} for RevokeSecurityGroupIngress on ALB SG
3. CloudWatch get-metric-statistics for RequestCount — is this a traffic surge?
""" + FORMAT_REMINDER

    # ── ALB 5xx ───────────────────────────────────────────────────────────────
    if alarm_type == "alb_5xx":
        return header + f"""
Investigate in this order:
1. elbv2 describe-target-health — are there any healthy targets?
2. CloudTrail lookup-events --start-time {two_hours_ago} for ModifyListener, DeleteRule, ModifyTargetGroup
3. CloudWatch get-metric-statistics for HealthyHostCount at same time as 5xx spike
""" + FORMAT_REMINDER

    # ── Target 5xx ────────────────────────────────────────────────────────────
    if alarm_type == "target_5xx":
        return header + f"""
Investigate in this order:
1. logs filter-log-events on Apache error log for 5xx patterns in last 2 hours
2. CloudWatch get-metric-statistics for CPUUtilization — resource exhaustion?
3. CloudTrail lookup-events --start-time {two_hours_ago} for UpdateService, RegisterTaskDefinition
""" + FORMAT_REMINDER

    # ── Status check failed ───────────────────────────────────────────────────
    if alarm_type == "status_check":
        return header + f"""
Investigate in this order:
1. CloudWatch get-metric-statistics for StatusCheckFailed_System and StatusCheckFailed_Instance
   → System failure = AWS hardware issue; Instance failure = OS/app crash
2. CloudTrail lookup-events --start-time {two_hours_ago} for StopInstances, RebootInstances, SSM commands
""" + FORMAT_REMINDER

    # ── ECS ──────────────────────────────────────────────────────────────────
    if alarm_type == "ecs":
        return header + f"""
Investigate in this order:
1. ecs describe-services for {dim_str} — desired vs running count, service events, stopped task reasons
2. CloudTrail lookup-events --start-time {two_hours_ago} for UpdateService, RegisterTaskDefinition
3. ecs list-tasks with desiredStatus=STOPPED — get exit codes
""" + FORMAT_REMINDER

    # ── Lambda errors ─────────────────────────────────────────────────────────
    if alarm_type == "lambda_error":
        return header + f"""
Investigate in this order — STOP at first confirmed cause:
1. CloudWatch logs filter-log-events on /aws/lambda/{dim_str} --start-time {two_hours_ago}
   → find the exact error message and stack trace
2. CloudTrail lookup-events --start-time {two_hours_ago} for UpdateFunctionCode, UpdateFunctionConfiguration
   → was the function recently redeployed with a bad version?
3. lambda get-function-configuration for {dim_str} — check timeout, memory, env vars
""" + FORMAT_REMINDER

    # ── Lambda throttles ──────────────────────────────────────────────────────
    if alarm_type == "lambda_throttle":
        return header + f"""
Investigate in this order:
1. CloudWatch get-metric-statistics for Throttles and ConcurrentExecutions for {dim_str}
2. lambda get-function-concurrency for {dim_str} — is reserved concurrency set too low?
3. CloudTrail lookup-events --start-time {two_hours_ago} for PutFunctionConcurrency
""" + FORMAT_REMINDER

    # ── ECS task count down ───────────────────────────────────────────────────
    if alarm_type == "ecs_task":
        return header + f"""
Investigate in this order — STOP at first confirmed cause:
1. ecs describe-services for {dim_str} — desired vs running count, last service events
2. CloudTrail lookup-events --start-time {two_hours_ago} for UpdateService
   → who scaled down the service and when?
3. ecs list-tasks --cluster <cluster> --desired-status STOPPED → describe stopped tasks for exit codes
4. If tasks are crashing: CloudWatch logs for the ECS task to find crash reason
""" + FORMAT_REMINDER

    # ── RDS high CPU ──────────────────────────────────────────────────────────
    if alarm_type == "rds_cpu":
        return header + f"""
Investigate in this order:
1. CloudWatch get-metric-statistics for CPUUtilization on {dim_str} for last 2 hours
   → confirm spike timing and peak value
2. rds describe-db-instances for {dim_str} — instance class, status, pending modified values
3. CloudTrail lookup-events --start-time {two_hours_ago} for CreateDBSnapshot, RestoreDBInstance,
   ModifyDBInstance — was a backup, restore, or schema change running?
4. CloudWatch get-metric-statistics for DatabaseConnections — sudden connection surge?
""" + FORMAT_REMINDER

    # ── RDS max connections ───────────────────────────────────────────────────
    if alarm_type == "rds_connections":
        return header + f"""
Investigate in this order:
1. CloudWatch get-metric-statistics for DatabaseConnections on {dim_str} for last 2 hours
   → confirm spike timing
2. rds describe-db-instances for {dim_str} — instance class (max_connections = RAM/12.5MB approx)
3. CloudTrail lookup-events --start-time {two_hours_ago} for ModifyDBInstance, CreateDBInstance
   → new app deployment or instance resize that affected connection pool?
4. CloudWatch get-metric-statistics for CPUUtilization — is DB also under compute pressure?
""" + FORMAT_REMINDER

    # ── RDS storage full ──────────────────────────────────────────────────────
    if alarm_type == "rds_storage":
        return header + f"""
Investigate in this order:
1. CloudWatch get-metric-statistics for FreeStorageSpace on {dim_str} for last 24 hours
   → how fast is storage being consumed?
2. rds describe-db-instances for {dim_str} — allocated storage, storage type, autoscaling enabled?
3. CloudTrail lookup-events --start-time {two_hours_ago} for CreateDBSnapshot — snapshots consuming space?
""" + FORMAT_REMINDER

    # ── Pattern 1: Public ALB → Palo Alto ENIC → EC2 (Business ACC) ──────────
    if alarm_type == "p1_alb_pa_ec2":
        return header + f"""
Architecture: Users → Public ALB (Network ACC) → Palo Alto ENIC → EC2 (Business ACC)

Investigate in this order — STOP and report at the first broken layer:

LAYER 1 — Palo Alto ENIC (Network ACC):
1. elbv2 describe-target-health for {dim_str} → are Palo Alto ENIC IPs healthy?
   If unhealthy:
   - ec2 describe-instances --filters Name=tag:Name,Values=*palo*alto* → PA instance running?
   - ec2 describe-network-interfaces → ENIC status=in-use and attached?
   - CloudTrail --start-time {two_hours_ago} for: StopInstances, TerminateInstances, DetachNetworkInterface
   If PA is the cause → report it. Do NOT check further.

LAYER 2 — EC2 Infrastructure (Business ACC):
2. ec2 describe-instances (business account EC2) → instance state=running?
   - CloudTrail --start-time {two_hours_ago} for: TerminateInstances, StopInstances
   - If terminated/stopped → root cause found, report it

3. ec2 describe-security-groups (EC2 SG) → inbound port 80/443 open from Palo Alto?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress, RevokeSecurityGroupEgress
   - If SG revoked → root cause found, report it

4. SSM list-command-invocations --filters key=InvokedAfter,value={two_hours_ago} --details
   → was httpd/nginx/app service stopped via SSM command?
   - If yes → root cause found, report it

LAYER 3 — EC2 Application Health:
5. CloudWatch get-metric-statistics for CPUUtilization (last 2 hours)
   → CPU > 90% sustained → process consuming all CPU, app unresponsive

6. CloudWatch get-metric-statistics for mem_used_percent (if CloudWatch agent installed)
   → Memory > 90% → OOM, app killed by OS

7. logs filter-log-events --log-group-name /ec2/app/error --start-time {two_hours_ago}
   → application error logs: exceptions, panics, segfaults, DB connection failures
   (try common log group names: /ec2/apache/error, /var/log/app, /ec2/nginx/error)

8. logs filter-log-events --log-group-name /ec2/app/access --start-time {two_hours_ago}
   → check if requests reaching app are returning 5xx (app-level errors not infra)

9. CloudWatch get-metric-statistics for disk_used_percent
   → disk > 95% → app cannot write logs/tmp files, crashes
""" + FORMAT_REMINDER

    # ── Pattern 2: Public ALB → Palo Alto ENIC → Internal NLB → ECS/EKS ─────
    if alarm_type == "p2_alb_pa_nlb_ecs":
        return header + f"""
Architecture: Users → Public ALB (Network ACC) → Palo Alto ENIC → Internal NLB → ECS/EKS (Business ACC)

Investigate in this order — STOP and report at the first broken layer:

LAYER 1 — Palo Alto ENIC (Network ACC):
1. elbv2 describe-target-health for {dim_str} → are Palo Alto ENIC IPs healthy?
   If unhealthy:
   - ec2 describe-instances --filters Name=tag:Name,Values=*palo*alto* → PA running?
   - CloudTrail --start-time {two_hours_ago} for: StopInstances, TerminateInstances, DetachNetworkInterface
   If PA is the cause → report it. Do NOT check further.

LAYER 2 — Internal NLB (Business ACC):
2. elbv2 describe-load-balancers → does Internal NLB still exist?
   - CloudTrail --start-time {two_hours_ago} for: DeleteLoadBalancer
   - If deleted → root cause found

3. elbv2 describe-listeners (NLB ARN) → listener still configured correctly?
   - CloudTrail --start-time {two_hours_ago} for: ModifyListener, DeleteListener
   - If modified/deleted → root cause found

4. ec2 describe-security-groups (NLB SG) → inbound open from Palo Alto?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on NLB SG
   - If revoked → root cause found

LAYER 3 — ECS / EKS Infrastructure (Business ACC):
5. ecs describe-services → desired vs running task count, service events
   - CloudTrail --start-time {two_hours_ago} for: DeleteService, UpdateService
   - If deleted or scaled to 0 → root cause found

6. ec2 describe-security-groups (ECS task SG) → inbound open from NLB?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on ECS SG
   - If revoked → root cause found

LAYER 4 — ECS / EKS Application Health:
7. ecs list-tasks --cluster <cluster> --desired-status STOPPED (last stopped tasks)
   ecs describe-tasks → stopCode and stoppedReason
   - Exit code 137 → OOMKilled (container ran out of memory)
   - Exit code 1 → application crash / unhandled exception
   - Exit code 143 → SIGTERM (task killed, possible deployment or scale-in)
   - Essential container exited → sidecar or app container crashed

8. logs filter-log-events --log-group-name /ecs/<service-name> --start-time {two_hours_ago}
   → application error logs: exceptions, DB connection failures, startup errors
   (try: /ecs/<service>, /aws/ecs/<cluster>/<service>, check ecs describe-task-definition for logConfiguration)

9. ecs describe-task-definition (current task def) → check image tag
   - CloudTrail --start-time {two_hours_ago} for: RegisterTaskDefinition, UpdateService
   - Bad image deployed recently? Compare previous vs current image tag

10. CloudWatch get-metric-statistics for ECS CPUUtilization and MemoryUtilization
    → CPU/memory at 100% → task throttled or OOMKilled
""" + FORMAT_REMINDER

    # ── Pattern 3: Public ALB → Palo Alto → NLB → Internal ALB → ECS/EKS ────
    if alarm_type == "p3_alb_pa_nlb_alb_ecs":
        return header + f"""
Architecture: Users → Public ALB (Network ACC) → Palo Alto ENIC → Internal NLB → Internal ALB → ECS/EKS (Business ACC)

Investigate in this order — STOP and report at the first broken layer:

LAYER 1 — Palo Alto ENIC (Network ACC):
1. elbv2 describe-target-health for {dim_str} → are Palo Alto ENIC IPs healthy?
   If unhealthy:
   - ec2 describe-instances --filters Name=tag:Name,Values=*palo*alto* → PA running?
   - CloudTrail --start-time {two_hours_ago} for: StopInstances, TerminateInstances, DetachNetworkInterface
   If PA is the cause → report it. Do NOT check further.

LAYER 2 — Internal NLB (Business ACC):
2. elbv2 describe-load-balancers → does Internal NLB still exist?
   - CloudTrail --start-time {two_hours_ago} for: DeleteLoadBalancer on NLB
   - If deleted → root cause found

3. elbv2 describe-listeners (NLB ARN) → listener configured correctly?
   - CloudTrail --start-time {two_hours_ago} for: ModifyListener, DeleteListener on NLB
   - If modified/deleted → root cause found

4. ec2 describe-security-groups (NLB SG) → inbound open from Palo Alto?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on NLB SG
   - If revoked → root cause found

LAYER 3 — Internal ALB (Business ACC):
5. elbv2 describe-load-balancers → does Internal ALB still exist?
   - CloudTrail --start-time {two_hours_ago} for: DeleteLoadBalancer on Internal ALB
   - If deleted → root cause found

6. ec2 describe-security-groups (Internal ALB SG) → inbound open from NLB?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on Internal ALB SG
   - If revoked → root cause found

LAYER 4 — ECS / EKS Infrastructure (Business ACC):
7. ecs describe-services → desired vs running count, service events
   - CloudTrail --start-time {two_hours_ago} for: DeleteService, UpdateService
   - If deleted or scaled to 0 → root cause found

8. ec2 describe-security-groups (ECS task SG) → inbound open from Internal ALB?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on ECS SG
   - If revoked → root cause found

LAYER 5 — ECS / EKS Application Health:
9. ecs list-tasks --cluster <cluster> --desired-status STOPPED
   ecs describe-tasks → stopCode and stoppedReason
   - Exit code 137 → OOMKilled (container ran out of memory)
   - Exit code 1 → application crash / unhandled exception
   - Exit code 143 → SIGTERM (task killed by deployment or scale-in)
   - Essential container exited → check which container and why

10. logs filter-log-events --log-group-name /ecs/<service-name> --start-time {two_hours_ago}
    → application error logs: exceptions, DB failures, startup errors
    (check ecs describe-task-definition for logConfiguration to get exact log group)

11. ecs describe-task-definition (current) → check image tag
    - CloudTrail --start-time {two_hours_ago} for: RegisterTaskDefinition, UpdateService
    - Bad image deployed? Compare current vs previous image tag

12. CloudWatch get-metric-statistics for ECS CPUUtilization and MemoryUtilization
    → sustained 100% → task throttled or about to be OOMKilled
""" + FORMAT_REMINDER

    # ── Pattern 4: Public ALB → Palo Alto → VPC Endpoint → API Gateway ───────
    if alarm_type == "p4_alb_pa_apigw":
        return header + f"""
Architecture: Users → Public ALB (Network ACC) → Palo Alto ENIC → VPC Interface Endpoint (execute-api) → API Gateway custom domain (Business ACC)

Investigate in this order — STOP and report at the first broken layer:

LAYER 1 — Palo Alto ENIC (Network ACC):
1. elbv2 describe-target-health for {dim_str} → are Palo Alto ENIC IPs healthy?
   If unhealthy:
   - ec2 describe-instances --filters Name=tag:Name,Values=*palo*alto* → PA running?
   - CloudTrail --start-time {two_hours_ago} for: StopInstances, TerminateInstances, DetachNetworkInterface
   If PA is the cause → report it. Do NOT check further.

LAYER 2 — VPC Interface Endpoint for API Gateway (Network ACC):
2. ec2 describe-vpc-endpoints --filters Name=service-name,Values=*execute-api*
   → state=available? If deleted or pending → root cause found
   - CloudTrail --start-time {two_hours_ago} for: DeleteVpcEndpoints, ModifyVpcEndpoint
   - If deleted → root cause found
   - If ModifyVpcEndpoint found → check what changed (subnets or security group)

3. ec2 describe-vpc-endpoints → check SubnetIds — were subnets removed/changed?
   - CloudTrail --start-time {two_hours_ago} for: ModifyVpcEndpoint with subnet changes
   - If subnets changed → root cause found

4. ec2 describe-security-groups (VPC endpoint SG) → inbound 443 open from ALB/Palo Alto?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on endpoint SG
   - If revoked → root cause found

LAYER 3 — API Gateway (Business ACC):
5. apigateway get-domain-name → custom domain still exists and configured?
   - CloudTrail --start-time {two_hours_ago} for: DeleteDomainName
6. apigateway get-base-path-mappings → mapped to correct API and stage?
   - CloudTrail --start-time {two_hours_ago} for: DeleteBasePathMapping, UpdateBasePathMapping
""" + FORMAT_REMINDER

    # ── Pattern 5: Public ALB → Palo Alto → VPC Endpoint → S3 ───────────────
    if alarm_type == "p5_alb_pa_s3":
        return header + f"""
Architecture: Users → Public ALB (Network ACC) → Palo Alto ENIC → VPC Interface Endpoint (S3) → S3 Bucket with custom domain (Business ACC)

Investigate in this order — STOP and report at the first broken layer:

LAYER 1 — Palo Alto ENIC (Network ACC):
1. elbv2 describe-target-health for {dim_str} → are Palo Alto ENIC IPs healthy?
   If unhealthy:
   - ec2 describe-instances --filters Name=tag:Name,Values=*palo*alto* → PA running?
   - CloudTrail --start-time {two_hours_ago} for: StopInstances, TerminateInstances, DetachNetworkInterface
   If PA is the cause → report it. Do NOT check further.

LAYER 2 — VPC Interface Endpoint for S3 (Network ACC):
2. ec2 describe-vpc-endpoints --filters Name=service-name,Values=*s3*
   → state=available? If deleted or pending → root cause found
   - CloudTrail --start-time {two_hours_ago} for: DeleteVpcEndpoints, ModifyVpcEndpoint
   - If deleted → root cause found
   - If ModifyVpcEndpoint found → check what changed (subnets or security group)

3. ec2 describe-vpc-endpoints → check SubnetIds — were subnets removed/changed?
   - CloudTrail --start-time {two_hours_ago} for: ModifyVpcEndpoint with subnet changes
   - If subnets changed → root cause found

4. ec2 describe-security-groups (VPC endpoint SG) → inbound 443 open from ALB/Palo Alto?
   - CloudTrail --start-time {two_hours_ago} for: RevokeSecurityGroupIngress on endpoint SG
   - If revoked → root cause found

LAYER 3 — S3 Bucket (Business ACC):
5. s3api get-bucket-policy (bucket name from custom domain) → allows s3:GetObject from VPC endpoint?
   - CloudTrail --start-time {two_hours_ago} for: PutBucketPolicy, DeleteBucketPolicy
   - If policy changed/removed → root cause found

6. s3api get-bucket-website → static website hosting still enabled?
   - CloudTrail --start-time {two_hours_ago} for: DeleteBucketWebsite, PutBucketWebsite
   - If disabled → root cause found
""" + FORMAT_REMINDER

    # ── Generic fallback ──────────────────────────────────────────────────────
    return header + f"""
Investigate in this order:
1. Describe current state of the resource: {dim_str}
2. CloudTrail lookup-events --start-time {two_hours_ago} for the affected resource
3. CloudWatch get-metric-statistics for {metric_name} around {timestamp}
""" + FORMAT_REMINDER


# ---------------------------------------------------------------------------
# Metric context extraction
# ---------------------------------------------------------------------------

def extract_metric_context(detail: dict) -> dict:
    metric_name = "Unknown Metric"
    namespace   = "Unknown Namespace"
    dimensions  = {}
    threshold   = None
    breach_val  = None

    try:
        metrics_cfg = detail.get("configuration", {}).get("metrics", [])
        if metrics_cfg:
            m = metrics_cfg[0].get("metricStat", {}).get("metric", {})
            metric_name = m.get("name", metric_name)
            namespace   = m.get("namespace", namespace)
            dimensions  = m.get("dimensions", {})
    except Exception as e:
        print(f"[WARN] Could not parse metric config: {e}")

    try:
        reason_data = json.loads(detail.get("state", {}).get("reasonData", "{}"))
        threshold   = reason_data.get("threshold")
        datapoints  = reason_data.get("recentDatapoints", [])
        breach_val  = datapoints[-1] if datapoints else None
    except Exception as e:
        print(f"[WARN] Could not parse reasonData: {e}")

    return {
        "metric_name":  metric_name,
        "namespace":    namespace,
        "dimensions":   dimensions,
        "threshold":    threshold,
        "breach_value": breach_val,
    }


# ---------------------------------------------------------------------------
# Agent call
# ---------------------------------------------------------------------------

def call_agent(incident_message: str) -> str:
    agent_url = os.environ["AGENT_URL"].rstrip("/")
    payload   = json.dumps({"message": incident_message, "history": []}).encode("utf-8")
    req = urllib.request.Request(
        f"{agent_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=150) as resp:
        return json.loads(resp.read().decode("utf-8")).get("response", "Empty response.")


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def get_recipients():
    r = [os.environ["EMAIL_RECIPIENT"]]
    if os.environ.get("EMAIL_RECIPIENT_2"):
        r.append(os.environ["EMAIL_RECIPIENT_2"])
    return r


ALARM_TYPE_LABELS = {
    "cpu":             ("🔥", "EC2 High CPU Utilization",      "#e65100"),
    "status_check":    ("💀", "EC2 Status Check Failed",        "#b71c1c"),
    "unhealthy_host":  ("⚠️",  "ALB Unhealthy Targets",         "#f57f17"),
    "no_healthy_host": ("🚨", "Service Completely Down",        "#b71c1c"),
    "rejected_conn":   ("🚫", "ALB Rejecting Connections",      "#6a1b9a"),
    "alb_5xx":         ("💥", "ALB 5xx Errors",                 "#c62828"),
    "target_5xx":      ("💥", "Application 5xx Errors",         "#ad1457"),
    "ecs":             ("📦", "ECS Tasks Not Running",           "#1565c0"),
    "ecs_task":            ("📦", "ECS Service Scaled Down",              "#1565c0"),
    "p1_alb_pa_ec2":       ("🖥️",  "ALB → Palo Alto → EC2 Incident",      "#b71c1c"),
    "p2_alb_pa_nlb_ecs":   ("🔗", "ALB → PA → NLB → ECS Incident",       "#b71c1c"),
    "p3_alb_pa_nlb_alb_ecs":("🔗","ALB → PA → NLB → ALB → ECS Incident", "#b71c1c"),
    "p4_alb_pa_apigw":     ("🌐", "ALB → PA → VPC Endpoint → API GW",    "#4a148c"),
    "p5_alb_pa_s3":        ("🪣", "ALB → PA → VPC Endpoint → S3",         "#004d40"),
    "lambda_error":    ("⚡", "Lambda Function Errors",          "#c62828"),
    "lambda_throttle": ("⚡", "Lambda Throttled",                "#6a1b9a"),
    "rds_cpu":         ("🗄️",  "RDS High CPU",                   "#e65100"),
    "rds_connections": ("🗄️",  "RDS Max Connections Reached",    "#b71c1c"),
    "rds_storage":     ("🗄️",  "RDS Storage Critical",           "#b71c1c"),
    "generic":         ("🚨", "Incident Detected",               "#37474f"),
}


def parse_rca_sections(rca: str) -> dict:
    """
    Extract PROBLEM / EVIDENCE / FIX sections from agent response.
    Falls back to raw text if format not found.
    """
    import re
    sections = {"problem": "", "evidence": "", "fix": "", "raw": rca}

    problem_match  = re.search(r"PROBLEM:\s*(.+?)(?=EVIDENCE:|FIX:|$)", rca, re.S | re.I)
    evidence_match = re.search(r"EVIDENCE:\s*(.+?)(?=FIX:|$)", rca, re.S | re.I)
    fix_match      = re.search(r"FIX:\s*(.+?)$", rca, re.S | re.I)

    if problem_match:
        sections["problem"]  = problem_match.group(1).strip()
    if evidence_match:
        sections["evidence"] = evidence_match.group(1).strip()
    if fix_match:
        sections["fix"]      = fix_match.group(1).strip()

    return sections


def send_rca_email(alarm_name, account_id, region, timestamp,
                   reason, metric_ctx, alarm_type, rca):
    metric_name   = metric_ctx["metric_name"]
    threshold     = metric_ctx["threshold"]
    breach_value  = metric_ctx["breach_value"]
    dim_str       = ", ".join(f"{k}={v}" for k, v in metric_ctx["dimensions"].items()) or "N/A"
    threshold_str = f"{threshold:.1f}"    if threshold   is not None else "N/A"
    breach_str    = f"{breach_value:.1f}" if breach_value is not None else "N/A"

    icon, label, color = ALARM_TYPE_LABELS.get(alarm_type, ALARM_TYPE_LABELS["generic"])
    sections = parse_rca_sections(rca)

    # Build RCA HTML — 3 clean panels if format parsed, fallback to raw
    if sections["problem"] or sections["evidence"] or sections["fix"]:
        rca_html = f"""
<table style="width:100%;border-collapse:separate;border-spacing:0 8px;">
  <tr>
    <td style="background:#fce4ec;border-left:4px solid #c62828;padding:14px 18px;border-radius:4px;">
      <div style="font-size:11px;font-weight:bold;color:#c62828;text-transform:uppercase;
                  letter-spacing:1px;margin-bottom:6px;">Problem</div>
      <div style="font-size:15px;color:#212121;">{sections['problem'] or '—'}</div>
    </td>
  </tr>
  <tr>
    <td style="background:#e8eaf6;border-left:4px solid #3949ab;padding:14px 18px;border-radius:4px;">
      <div style="font-size:11px;font-weight:bold;color:#3949ab;text-transform:uppercase;
                  letter-spacing:1px;margin-bottom:6px;">Evidence</div>
      <div style="font-size:13px;color:#212121;white-space:pre-wrap;font-family:monospace;">
        {sections['evidence'] or '—'}</div>
    </td>
  </tr>
  <tr>
    <td style="background:#e8f5e9;border-left:4px solid #2e7d32;padding:14px 18px;border-radius:4px;">
      <div style="font-size:11px;font-weight:bold;color:#2e7d32;text-transform:uppercase;
                  letter-spacing:1px;margin-bottom:6px;">Fix</div>
      <div style="font-size:13px;color:#212121;white-space:pre-wrap;font-family:monospace;">
        {sections['fix'] or '—'}</div>
    </td>
  </tr>
</table>"""
    else:
        # Fallback: raw response
        rca_html = f"""<div style="white-space:pre-wrap;font-size:13px;
                        font-family:monospace;color:#212121;">{rca}</div>"""

    html_body = f"""
<html><body style="font-family:Arial,sans-serif;max-width:780px;margin:0 auto;">

<div style="background:{color};color:white;padding:18px 22px;border-radius:8px 8px 0 0;">
  <h2 style="margin:0;font-size:18px;">{icon} {label}</h2>
  <p style="margin:5px 0 0;opacity:0.85;font-size:13px;">{alarm_name}</p>
</div>

<table style="width:100%;border-collapse:collapse;background:#fafafa;
              border:1px solid #e0e0e0;border-top:none;font-size:13px;">
  <tr>
    <td style="padding:8px 16px;color:#757575;width:130px;">Metric</td>
    <td style="padding:8px 16px;font-weight:bold;">{metric_name} &nbsp;|&nbsp; Actual: <span style="color:#c62828;">{breach_str}</span> &nbsp;/&nbsp; Threshold: {threshold_str}</td>
  </tr>
  <tr style="background:#f5f5f5;">
    <td style="padding:8px 16px;color:#757575;">Resource</td>
    <td style="padding:8px 16px;">{dim_str}</td>
  </tr>
  <tr>
    <td style="padding:8px 16px;color:#757575;">Account / Region</td>
    <td style="padding:8px 16px;">{account_id} / {region}</td>
  </tr>
  <tr style="background:#f5f5f5;">
    <td style="padding:8px 16px 10px;color:#757575;">Time (UTC)</td>
    <td style="padding:8px 16px 10px;">{timestamp}</td>
  </tr>
</table>

<div style="padding:18px 20px;border:1px solid #e0e0e0;border-top:none;background:white;">
  {rca_html}
</div>

<div style="background:#f5f5f5;padding:8px 16px;border-radius:0 0 8px 8px;
            font-size:11px;color:#9e9e9e;border:1px solid #e0e0e0;border-top:none;">
  AWS Incident Response Agent &bull; {timestamp} &bull; {alarm_type.replace('_',' ').title()}
</div>

</body></html>
"""
    ses = boto3.client("ses", region_name=os.environ["SES_REGION"])
    ses.send_email(
        Source=os.environ["EMAIL_SENDER"],
        Destination={"ToAddresses": get_recipients()},
        Message={
            "Subject": {
                "Data": f"[{alarm_type.replace('_',' ').upper()}] {icon} {alarm_name} — RCA Complete",
                "Charset": "UTF-8",
            },
            "Body": {"Html": {"Data": html_body, "Charset": "UTF-8"}},
        },
    )


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    print(f"Event: {json.dumps(event)}")

    detail     = event.get("detail", {})
    alarm_name = detail.get("alarmName", "Unknown Alarm")
    state      = detail.get("state", {}).get("value", "UNKNOWN")
    reason     = detail.get("state", {}).get("reason", "")
    account_id = event.get("account", "Unknown")
    region     = event.get("region", "Unknown")
    timestamp  = event.get("time", datetime.now(timezone.utc).isoformat())

    if state != "ALARM":
        print(f"Skipping: state={state}")
        return {"statusCode": 200, "body": f"Skipped: {state}"}

    # Extract metric context and classify alarm type
    metric_ctx = extract_metric_context(detail)
    alarm_type = detect_alarm_type(alarm_name, metric_ctx["metric_name"])
    print(f"Alarm type: {alarm_type} | Metric: {metric_ctx['metric_name']}")

    # Build targeted prompt based on alarm type
    incident_message = build_incident_message(
        alarm_name, account_id, region, timestamp,
        reason, metric_ctx, alarm_type
    )
    print(f"Prompt built ({len(incident_message)} chars) for type: {alarm_type}")

    # Call agent
    rca = call_agent(incident_message)
    print(f"RCA received ({len(rca)} chars)")

    # Send email
    send_rca_email(alarm_name, account_id, region, timestamp,
                   reason, metric_ctx, alarm_type, rca)
    recipients = get_recipients()
    print(f"RCA email sent to: {recipients}")

    return {"statusCode": 200, "body": f"Done. Type={alarm_type}. Sent to {recipients}"}
