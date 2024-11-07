# AWS Cloud Security Posture Assessment Tool - University of Derby.
# This tool is developed for a research project at University of Derby.
# Author: Kyaw Htet Aung 
# University of Derby
# main.py

import aws_scanner

def main():
    print("Welcome to the AWS Cloud Security Posture Assessment Tool by Kyaw Htet Aung - University of Derby")
    
    aws_profile = input("Enter your AWS profile name: ")
    aws_region = input("Enter AWS region (e.g., us-east-1): ")

    try:
        scanner = aws_scanner.AWSScanner(aws_profile, aws_region)
        scanner.check_public_s3_buckets()
        scanner.check_iam_unused_access_keys()
        scanner.check_security_group_permissions()
        scanner.check_iam_users_without_mfa()
        scanner.check_unencrypted_ebs_volumes()
        scanner.check_cloudtrail_enabled()
        scanner.check_overly_permissive_user_policies()
        scanner.check_inactive_high_privilege_roles()
        scanner.summarize_findings()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

