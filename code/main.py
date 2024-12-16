# AWS Cloud Security Posture Assessment Tool - University of Derby.
# This tool is developed for a research project at University of Derby.
# Author: Kyaw Htet Aung 
# University of Derby

import aws_scanner

def main():
    print("Welcome to the AWS Cloud Security Posture Assessment Tool by Kyaw Htet Aung - University of Derby")
    
    aws_profile = input("Enter your AWS profile name: ")
    aws_region = input("Enter AWS region (e.g., us-east-1): ")
    log_file = input("Enter the file name to save findings (default: findings.log): ") or "findings.log"

    try:
        scanner = aws_scanner.AWSScanner(aws_profile, aws_region, log_file)
        scanner.check_iam_access_keys_inactive_90_days()
        scanner.check_iam_users_without_mfa()
        scanner.check_unencrypted_ebs_volumes()
        scanner.summarize_findings()
        print(f"\nFindings saved to: {log_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()