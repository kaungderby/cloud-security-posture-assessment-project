# AWS Cloud Security Posture Assessment Tool - University of Derby.
# This tool is developed for a research project at University of Derby.
# Author: Kyaw Htet Aung 
# University of Derby

import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import os
from genai import ask_user_for_genai, get_openai_suggestion

class AWSScanner:
    def __init__(self, profile_name, region_name):
        session = boto3.Session(profile_name=profile_name)
        self.s3 = session.client('s3', region_name=region_name)
        self.iam = session.client('iam', region_name=region_name)
        self.ec2 = session.client('ec2', region_name=region_name)
        self.cloudtrail = session.client('cloudtrail', region_name=region_name)
        self.findings = []
        self.already_suggested = set()

    def check_iam_users_without_mfa(self):
        """Check for IAM users without MFA enabled"""
        try:
            users = self.iam.list_users()
            for user in users['Users']:
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices['MFADevices']:
                    alert = f"ALERT: IAM user '{user['UserName']}' does not have MFA enabled."
                    self.findings.append(alert)
        except ClientError as e:
            print(f"Error checking IAM users without MFA: {e}")

    def check_iam_keys_inactive(self, days=90):
        """Check for IAM access keys that have been inactive for more than the specified days"""
        try:
            current_date = datetime.utcnow()
            users = self.iam.list_users()

            for user in users['Users']:
                access_keys = self.iam.list_access_keys(UserName=user['UserName'])
                for key in access_keys['AccessKeyMetadata']:
                    last_used = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                    if last_used_date:
                        inactive_days = (current_date - last_used_date.replace(tzinfo=None)).days
                        if inactive_days > days:
                            alert = f"ALERT: IAM access key '{key['AccessKeyId']}' for user '{user['UserName']}' is inactive for {inactive_days} days."
                            self.findings.append(alert)
        except ClientError as e:
            print(f"Error checking IAM inactive access keys: {e}")

    def check_unencrypted_ebs_volumes(self):
        """Check for unencrypted EBS volumes"""
        try:
            volumes = self.ec2.describe_volumes()
            for volume in volumes['Volumes']:
                if not volume['Encrypted']:
                    alert = f"ALERT: EBS volume '{volume['VolumeId']}' is not encrypted."
                    self.findings.append(alert)
        except ClientError as e:
            print(f"Error checking EBS encryption: {e}")

    def check_cloudtrail_status(self):
        """Check for misconfigured CloudTrail"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            for trail in trails:
                if not trail.get('IsMultiRegionTrail') or not trail.get('LogFileValidationEnabled'):
                    alert = f"ALERT: CloudTrail '{trail['Name']}' is misconfigured."
                    if not trail.get('IsMultiRegionTrail'):
                        alert += " Multi-region is disabled."
                    if not trail.get('LogFileValidationEnabled'):
                        alert += " Log file validation is disabled."
                    self.findings.append(alert)
        except ClientError as e:
            print(f"Error checking CloudTrail configuration: {e}")

    def summarize_findings(self):
        """Summarize security findings"""
        print("\nSummary of Findings:")
        for finding in self.findings:
            print(f"- {finding}")

        # Ask user if they want to enable GenAI recommendations
        use_genai = ask_user_for_genai()
        if use_genai:
            self.provide_genai_recommendations()

    def provide_genai_recommendations(self):
        """Provide AI-powered security recommendations"""
        print("\nGenerating AI-based recommendations...")
        issue_types = set()

        for finding in self.findings:
            if "IAM user" in finding and "MFA" in finding:
                issue_types.add("IAM users without MFA enabled")
            elif "EBS volume" in finding and "not encrypted" in finding:
                issue_types.add("Unencrypted EBS volumes")
            elif "IAM access key" in finding and "inactive" in finding:
                issue_types.add("Inactive IAM access keys")
            elif "CloudTrail" in finding and "misconfigured" in finding:
                issue_types.add("Misconfigured CloudTrail")

        for issue in issue_types:
            suggestion = get_openai_suggestion(issue)
            if suggestion:
                print(f"\nRemediation Suggestion for {issue}: {suggestion}")
