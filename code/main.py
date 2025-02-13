import os
import aws_scanner

def main():
    print("\nWelcome to the AWS Cloud Security Posture Assessment Tool\n")
    
    # Prompt for AWS credentials
    aws_profile = input("Enter your AWS profile name (default): ") or "default"
    aws_region = input("Enter AWS region (e.g., us-east-1): ") or "us-east-1"
    
    # Initialize scanner
    scanner = aws_scanner.AWSScanner(aws_profile, aws_region)
    
    print("\nRunning AWS Security Checks...\n")
    
    # Run security checks
    scanner.check_iam_users_without_mfa()
    scanner.check_unencrypted_ebs_volumes()
    
    # Summarize findings
    scanner.summarize_findings()
    
    print("\nSecurity Scan Complete. Review the findings above.")

if __name__ == "__main__":
    main()
