# Cloud Security Posture Assessment Research Project

This project is developed as part of a research initiative for a Cyber Security program at the University of Derby. The aim of this research is to address the risks associated with cloud security misconfigurations by developing a Python-based, command-line interface (CLI) tool. This tool is specifically designed to help organizations, particularly those with limited resources, assess and improve their cloud security posture.

# Project Background
Cloud computing has become vital for various organizations, including enterprises and non-profits (NPOs), due to its scalability, flexibility, and cost-efficiency. However, it also introduces significant security risks, particularly through misconfigurations, which can leave cloud resources vulnerable to cyber-attacks and data breaches.

Given the financial constraints and limited access to advanced security tools faced by smaller organizations and NPOs, this project is dedicated to creating a cost-effective, open-source tool. This tool will enable these organizations to detect, mitigate, and prevent misconfigurations in their cloud environments, particularly within AWS, and to strengthen their overall cloud security posture. Future contributions will aim to expand the tool’s capabilities to support additional cloud platforms.

# Getting Started
This tool performs a security assessment on your AWS account by identifying common misconfigurations. It checks for publicly accessible S3 buckets, IAM users without MFA, unencrypted EBS volumes, and more.

## Prerequisites
1. Python 3.7+ is required. Ensure you have Python installed:

```bash
python3 --version
```

2. Install boto3: This tool relies on the boto3 library to interact with AWS services. You can install it using pip. You can create a requirements.txt File: In your project directory, create a file named requirements.txt and add boto3 to it. Here’s what the file should look like:

```bash
boto3
```

>This ensures that anyone running the tool can install boto3 (and any other future dependencies) with one command.

Install Dependencies from requirements.txt: After cloning the repository and setting up a virtual environment (recommended), install all dependencies using the following command:

```bash
pip install -r requirements.txt
```

>This command tells pip to read from requirements.txt and install the necessary libraries, including boto3.

## AWS CLI and Credentials:

Set up the AWS CLI with your credentials. You can configure a profile using:
```bash
aws configure --profile your_profile_name
```

Alternatively, provide AWS credentials directly in your environment if preferred.

## Installation Instructions
Clone the Repository: Clone this repository to your local machine:

```bash
git clone https://github.com/kaungderby/cloud-security-posture-assessment-project.git
cd cloud-security-posture-assessment-project
```

Set Up a Virtual Environment (Recommended): To avoid any conflicts with other projects, create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Required Packages: Install boto3 and any other dependencies in the virtual environment:

```bash
pip install boto3
```

## Running the Script
1. Activate the Virtual Environment (if not already active):

```bash
source venv/bin/activate
```

2. Run the Script: Execute the main Python script to begin the security assessment:

```bash
python code/main.py
```

>Input AWS Profile and Region:

When prompted, enter your AWS profile name (as configured in the AWS CLI) and region (e.g., us-east-1 or ap-southeast-1).
Review Results:

The tool will output alerts for any misconfigurations it detects and summarize findings at the end.

### Deactivating the Virtual Environment
When you’re done, deactivate the virtual environment:

```bash
deactivate
```