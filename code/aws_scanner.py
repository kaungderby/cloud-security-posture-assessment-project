# aws_scanner.py

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

class AWSScanner:
    def __init__(self, profile_name, region_name):
        session = boto3.Session(profile_name=profile_name)
        self.s3 = session.client('s3', region_name=region_name)
        self.iam = session.client('iam', region_name=region_name)
        self.ec2 = session.client('ec2', region_name=region_name)
        self.cloudtrail = session.client('cloudtrail', region_name=region_name)
        self.findings_count = 0

    def check_public_s3_buckets(self):
        print("Checking for public S3 buckets...")
        findings = []
        try:
            buckets = self.s3.list_buckets()
            for bucket in buckets['Buckets']:
                acl = self.s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    if grant['Permission'] == 'READ' and 'AllUsers' in str(grant['Grantee']):
                        findings.append(bucket['Name'])
                        print(f"ALERT: Bucket '{bucket['Name']}' is publicly accessible!")
            if not findings:
                print("No publicly accessible S3 buckets found.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            print(f"Error checking S3 buckets: {e}")

    def check_iam_unused_access_keys(self):
        print("Checking for IAM users with unused access keys...")
        findings = []
        try:
            users = self.iam.list_users()
            for user in users['Users']:
                access_keys = self.iam.list_access_keys(UserName=user['UserName'])
                for key in access_keys['AccessKeyMetadata']:
                    last_used = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    if 'LastUsedDate' not in last_used['AccessKeyLastUsed']:
                        findings.append((user['UserName'], key['AccessKeyId']))
                        print(f"ALERT: Access key '{key['AccessKeyId']}' for user '{user['UserName']}' has never been used!")
            if not findings:
                print("No unused IAM access keys found.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            print(f"Error checking IAM access keys: {e}")

    def check_security_group_permissions(self):
        print("Checking for overly permissive security group rules...")
        findings = []
        try:
            security_groups = self.ec2.describe_security_groups()
            for sg in security_groups['SecurityGroups']:
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':
                            findings.append((sg['GroupId'], rule.get('FromPort'), rule.get('ToPort')))
                            print(f"ALERT: Security Group '{sg['GroupId']}' has open access on port range {rule.get('FromPort')}-{rule.get('ToPort')}.")
            if not findings:
                print("No overly permissive security group rules found.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            print(f"Error checking security groups: {e}")

    def check_iam_users_without_mfa(self):
        print("Checking for IAM users without MFA enabled...")
        findings = []
        try:
            users = self.iam.list_users()
            for user in users['Users']:
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                if len(mfa_devices['MFADevices']) == 0:
                    findings.append(user['UserName'])
                    print(f"ALERT: IAM user '{user['UserName']}' does not have MFA enabled.")
            if not findings:
                print("All IAM users have MFA enabled.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            print(f"Error checking IAM users for MFA: {e}")

    def check_unencrypted_ebs_volumes(self):
        print("Checking for unencrypted EBS volumes...")
        findings = []
        try:
            volumes = self.ec2.describe_volumes()
            for volume in volumes['Volumes']:
                if not volume['Encrypted']:
                    findings.append(volume['VolumeId'])
                    print(f"ALERT: EBS volume '{volume['VolumeId']}' is not encrypted.")
            if not findings:
                print("All EBS volumes are encrypted.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            print(f"Error checking EBS volumes for encryption: {e}")

    def check_cloudtrail_enabled(self):
        print("Checking if CloudTrail is enabled...")
        try:
            trails = self.cloudtrail.describe_trails()
            if len(trails['trailList']) == 0:
                print("ALERT: No CloudTrail is enabled.")
                self.findings_count += 1
            else:
                print("CloudTrail is enabled.")
        except ClientError as e:
            print(f"Error checking CloudTrail: {e}")

    def summarize_findings(self):
        if self.findings_count == 0:
            print("\nAssessment Complete: No findings detected. Your AWS account is configured securely based on the assessed checks.")
        else:
            print(f"\nAssessment Complete: {self.findings_count} finding(s) detected. Please review the alerts above for details.")
