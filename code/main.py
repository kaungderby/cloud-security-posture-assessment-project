# main.py
# Welcome to the AWS Cloud Security Posture Assessment Tool - Derby University
# Author: Kyaw Htet Aung 
# University of Derby

# main.py

import aws_scanner

def main():
    print("Welcome to the AWS Cloud Security Posture Assessment Tool - Derby University")
    
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
        scanner.summarize_findings()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

