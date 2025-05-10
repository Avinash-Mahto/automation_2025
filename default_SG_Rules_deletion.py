import boto3
import json
import logging
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ROLE_NAME = 'CrossAccountSGLambdaRole'  # Update if different

def get_all_account_ids():
    org_client = boto3.client('organizations')
    accounts = []
    paginator = org_client.get_paginator('list_accounts')

    for page in paginator.paginate():
        for acct in page['Accounts']:
            if acct['Status'] == 'ACTIVE':
                accounts.append(acct['Id'])

    return accounts

def assume_role(account_id):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='CrossAccountSGCheck'
    )
    creds = response['Credentials']
    return boto3.client(
        'ec2',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )

def process_account(account_id):
    try:
        ec2_client = assume_role(account_id)

        # Get all VPCs
        vpcs = ec2_client.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']

            # Find default SG
            sg_response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            )

            if not sg_response['SecurityGroups']:
                logger.info(f"No default SG in account {account_id}, VPC {vpc_id}")
                continue

            sg = sg_response['SecurityGroups'][0]
            sg_id = sg['GroupId']

            if sg['IpPermissions']:
                ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=sg['IpPermissions']
                )
                logger.info(f"Revoked inbound rules in {sg_id} (Account: {account_id})")

            if sg['IpPermissionsEgress']:
                ec2_client.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=sg['IpPermissionsEgress']
                )
                logger.info(f"Revoked outbound rules in {sg_id} (Account: {account_id})")

    except Exception as e:
        logger.error(f"Error processing account {account_id}: {str(e)}")

def lambda_handler(event, context):
    account_ids = get_all_account_ids()
    logger.info(f"Found {len(account_ids)} accounts.")
    for account_id in account_ids:
        logger.info(f"Processing Account: {account_id}")
        process_account(account_id)
