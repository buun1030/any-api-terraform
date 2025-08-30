#!/bin/bash
set -e

# Install and start Docker
sudo yum update -y
sudo yum install -y docker
sudo yum install -y jq
sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Authenticate Docker to your ECR registry
aws ecr get-login-password --region ${aws_region} | docker login --username AWS --password-stdin ${aws_account_id}.dkr.ecr.${aws_region}.amazonaws.com

# Pull the Docker image
docker pull ${aws_account_id}.dkr.ecr.${aws_region}.amazonaws.com/any-api-backend:latest

# The name of your key/value secret
SECRET_ID="${secret_id}"
REGION="${aws_region}"

# Fetch the secret JSON from AWS Secrets Manager
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" --region "$REGION" --output json)

# Use jq to parse the nested JSON and extract each value
DB_ENGINE=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .engine')
DB_USER=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .username')
DB_PASSWORD=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .password | @uri')
DB_HOST=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .host')
DB_PORT=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .port')
DB_NAME=$(echo "$SECRET_JSON" | jq -r '.SecretString | fromjson | .dbname')

# Construct the full DATABASE_URL from the parts
DATABASE_URL="$${DB_ENGINE}://$${DB_USER}:$${DB_PASSWORD}@$${DB_HOST}:$${DB_PORT}/$${DB_NAME}"

# Run the Docker container with the secret
sudo docker run -d --rm --pull=always -p 8080:8080 -e DATABASE_URL="$DATABASE_URL" ${aws_account_id}.dkr.ecr.${aws_region}.amazonaws.com/any-api:latest
