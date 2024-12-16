# AWS Cloud Security Posture Assessment Tool - University of Derby.
# This tool is developed for a research project at University of Derby.
# Author: Kyaw Htet Aung 
# University of Derby

import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone

class AWSScanner:
    def __init__(self, profile_name, region_name, log_file='findings.log'):
        session = boto3.Session(profile_name=profile_name)
        self.s3 = session.client('s3', region_name=region_name)
        self.iam = session.client('iam', region_name=region_name)
        self.ec2 = session.client('ec2', region_name=region_name)
        self.findings_count = 0
        self.log_file = log_file
        open(self.log_file, 'w').close()  # Clear the log file at start

    def log_finding(self, message):
        print(message)
        with open(self.log_file, 'a') as f:
            f.write(f"{message}\n")

    def check_iam_access_keys_inactive_90_days(self):
        print("Checking for IAM users with access keys inactive for 90+ days...")
        findings = []
        threshold_date = datetime.now(timezone.utc) - timedelta(days=90)  # Make timezone-aware
        try:
            users = self.iam.list_users()
            for user in users['Users']:
                access_keys = self.iam.list_access_keys(UserName=user['UserName'])
                for key in access_keys['AccessKeyMetadata']:
                    last_used_response = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    last_used_date = last_used_response['AccessKeyLastUsed'].get('LastUsedDate')

                    if last_used_date:  # If the key has been used before
                        if last_used_date < threshold_date:  # Compare timezone-aware datetimes
                            findings.append((user['UserName'], key['AccessKeyId'], last_used_date))
                            self.log_finding(
                                f"ALERT: Access key '{key['AccessKeyId']}' for user '{user['UserName']}' "
                                f"has not been used since {last_used_date.strftime('%Y-%m-%d')}!"
                            )
                    else:  # If the key has never been used
                        findings.append((user['UserName'], key['AccessKeyId'], "Never Used"))
                        self.log_finding(
                            f"ALERT: Access key '{key['AccessKeyId']}' for user '{user['UserName']}' has NEVER been used!"
                        )
        except ClientError as e:
            self.log_finding(f"Error checking IAM access keys: {e}")

        if not findings:
            self.log_finding("No IAM access keys inactive for more than 90 days were found.")
        else:
            self.findings_count += len(findings)

    def check_iam_users_without_mfa(self):
        print("Checking for IAM users without MFA enabled...")
        findings = []
        try:
            users = self.iam.list_users()
            for user in users['Users']:
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                if len(mfa_devices['MFADevices']) == 0:
                    findings.append(user['UserName'])
                    self.log_finding(f"ALERT: IAM user '{user['UserName']}' does not have MFA enabled.")
            if not findings:
                self.log_finding("All IAM users have MFA enabled.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            self.log_finding(f"Error checking IAM users for MFA: {e}")

    def check_unencrypted_ebs_volumes(self):
        print("Checking for unencrypted EBS volumes...")
        findings = []
        try:
            volumes = self.ec2.describe_volumes()
            for volume in volumes['Volumes']:
                if not volume['Encrypted']:
                    findings.append(volume['VolumeId'])
                    self.log_finding(f"ALERT: EBS volume '{volume['VolumeId']}' is not encrypted.")
            if not findings:
                self.log_finding("All EBS volumes are encrypted.")
            else:
                self.findings_count += len(findings)
        except ClientError as e:
            self.log_finding(f"Error checking EBS volumes for encryption: {e}")

    def summarize_findings(self):
        if self.findings_count == 0:
            self.log_finding("\nAssessment Complete: No findings detected. Your AWS account is configured securely based on the assessed checks.")
        else:
            self.log_finding(f"\nAssessment Complete: {self.findings_count} finding(s) detected. Please review the alerts above for details.")
