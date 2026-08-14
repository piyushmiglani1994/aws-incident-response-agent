"""
Generic AWS API tool for the incident response agent.
Allows the LangGraph ReAct agent to call any AWS API action
dynamically using boto3, with cross-account role assumption.

Required environment variables:
  NETWORK_ACCOUNT_ID   - AWS account ID for the network/inspection account
  BUSINESS_ACCOUNT_ID  - AWS account ID for the business/workload account
  AGENT_ROLE_ARN       - IAM role ARN the agent assumes for cross-account access
                         (if not set, uses the task's default credentials)
"""

import os
import json
import boto3
from langchain_core.tools import tool

# Optional: role ARN for cross-account access
AGENT_ROLE_ARN = os.environ.get("AGENT_ROLE_ARN", "")


def get_client(account_id: str, service: str, region: str = "us-east-1"):
    """
    Return a boto3 client for the given service.
    If AGENT_ROLE_ARN is set, assumes that role in the target account.
    Otherwise uses the current execution role credentials.
    """
    if AGENT_ROLE_ARN:
        sts = boto3.client("sts", region_name=region)
        assumed = sts.assume_role(
            RoleArn=AGENT_ROLE_ARN.format(account_id=account_id),
            RoleSessionName="IncidentResponseAgent",
        )
        creds = assumed["Credentials"]
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    # Use task execution role (IAM role attached to ECS task)
    return boto3.client(service, region_name=region)


@tool
def aws_api_call(
    account_id: str,
    service: str,
    action: str,
    region: str = "us-east-1",
    parameters: str = "{}",
) -> str:
    """
    Call any AWS API action and return the JSON response.

    Args:
        account_id: AWS account ID to call the API in
        service:    boto3 service name (e.g. 'ec2', 'ecs', 'elbv2', 'cloudtrail')
        action:     boto3 method name (e.g. 'describe_instances', 'lookup_events')
        region:     AWS region (default: us-east-1)
        parameters: JSON string of kwargs to pass to the boto3 method

    Returns:
        JSON string of the API response (ResponseMetadata stripped),
        or an error string prefixed with 'Error:'.
    """
    try:
        client = get_client(account_id, service, region)
        params = json.loads(parameters)
        method = getattr(client, action)
        response = method(**params)
        response.pop("ResponseMetadata", None)
        return json.dumps(response, default=str)

    except AttributeError:
        return (
            f"Error: service '{service}' does not support action '{action}'. "
            f"Check boto3 docs for valid method names."
        )
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON in parameters: {e}"
    except Exception as e:
        return f"Error calling {service}.{action}: {e}"
