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
        users = self.iam.list_users()
        for user in users['Users']:
            mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                self.findings.append(f"ALERT: IAM user '{user['UserName']}' does not have MFA enabled.")

    def check_unencrypted_ebs_volumes(self):
        volumes = self.ec2.describe_volumes()
        for volume in volumes['Volumes']:
            if not volume['Encrypted']:
                self.findings.append(f"ALERT: EBS volume '{volume['VolumeId']}' is not encrypted.")

    def summarize_findings(self):
        print("\nSummary of Findings:")
        for finding in self.findings:
            print(f"- {finding}")
        
        # Ask if the user wants to see GenAI recommendations after assessment
        use_genai = ask_user_for_genai()
        if use_genai:
            self.provide_genai_recommendations()

    def provide_genai_recommendations(self):
        """Provide GenAI-powered recommendations for identified issues."""
        print("\nGenerating AI-based recommendations...")
        issue_types = set()
        for finding in self.findings:
            if "IAM user" in finding and "MFA" in finding:
                issue_types.add("IAM users without MFA enabled")
            elif "EBS volume" in finding and "not encrypted" in finding:
                issue_types.add("Unencrypted EBS volumes")
        
        for issue in issue_types:
            suggestion = get_openai_suggestion(issue)
            if suggestion:
                print(f"\nRemediation Suggestion for {issue}: {suggestion}")