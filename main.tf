terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-2"
}

provider "tls" {}

# Data source to fetch the secret from AWS Secrets Manager
data "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = "any-api/db-user-pass"
}

# Local variable to parse the JSON secret string
locals {
  db_creds = jsondecode(data.aws_secretsmanager_secret_version.db_credentials.secret_string)
}

resource "tls_private_key" "any_api_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "any_api_key" {
  key_name   = "any-api-key"
  public_key = tls_private_key.any_api_key.public_key_openssh
}

resource "local_file" "any_api_key_pem" {
  content  = tls_private_key.any_api_key.private_key_pem
  filename = "any-api-key.pem"
}

# --- IAM Role for EC2 (Self-Contained) ---

# The policy document allowing EC2 to assume this role
data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# The IAM role itself
resource "aws_iam_role" "ec2_any_api_role" {
  name               = "ec2-any-api-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

# The policy that allows reading the specific secret
data "aws_iam_policy_document" "secrets_manager_policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    # This dynamically uses the ARN of the secret data source from earlier
    resources = [data.aws_secretsmanager_secret_version.db_credentials.arn]
  }
}

# Attach the policy to the role
resource "aws_iam_role_policy" "secrets_manager_policy_attachment" {
  name   = "allow-read-database-secret"
  role   = aws_iam_role.ec2_any_api_role.id
  policy = data.aws_iam_policy_document.secrets_manager_policy.json
}

# The instance profile, which is what gets attached to the EC2 instance
resource "aws_iam_instance_profile" "ec2_any_api_profile" {
  name = "ec2-any-api-role"
  role = aws_iam_role.ec2_any_api_role.name
}

resource "aws_iam_role_policy_attachment" "ecr_read_only_attachment" {
  role       = aws_iam_role.ec2_any_api_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# --- End IAM Role ---

data "aws_caller_identity" "current" {}

resource "aws_instance" "any_api_backend_server" {
  ami           = "ami-093dc6859d9315726"
  instance_type = "t3.micro"
  key_name      = aws_key_pair.any_api_key.key_name
  user_data = templatefile("${path.module}/scripts/run-any-api.sh.tpl", {
    aws_account_id = data.aws_caller_identity.current.account_id
    aws_region     = "ap-southeast-2"
    secret_id      = data.aws_secretsmanager_secret_version.db_credentials.secret_id
  })
  subnet_id              = "subnet-0e175c6eb8916ef25"
  vpc_security_group_ids = [aws_security_group.any_api_backend_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_any_api_profile.name
  tags = {
    Name = "any-api-backend-server"
  }
}

resource "aws_db_instance" "any_api_postgres_db_v2" {
  allocated_storage = 20
  instance_class    = "db.t4g.micro"
  engine            = "postgres"
  engine_version    = "17.4"
  identifier        = "any-api-postgres-db-v2"
  username          = local.db_creds.username
  password          = local.db_creds.password
  db_name           = local.db_creds.dbname
  # identifier           = "any-api-postgres-db-v2-restored"                                                                                             │
  # snapshot_identifier  = "any-api-db-final-snapshot-${timestamp()}"
  vpc_security_group_ids     = [aws_security_group.any_api_rds_sg.id]
  db_subnet_group_name       = aws_db_subnet_group.any_api_rds_subnet_group.name
  skip_final_snapshot        = false
  final_snapshot_identifier  = "any-api-db-final-snapshot-${formatdate("YYYY-MM-DD-hh-mm-ss", timestamp())}"
  auto_minor_version_upgrade = false
  copy_tags_to_snapshot      = true
  publicly_accessible        = false
}

# A group of private subnets for the RDS instance
resource "aws_db_subnet_group" "any_api_rds_subnet_group" {
  name       = "any-api-rds-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Name = "Any API RDS private subnet group"
  }
}

# Private Subnet in AZ A
resource "aws_subnet" "private_a" {
  vpc_id            = "vpc-0549027f59f08d65c"
  cidr_block        = "172.30.4.0/24"
  availability_zone = "ap-southeast-2a"

  tags = {
    Name = "any-api-private-subnet-a"
  }
}

# Private Subnet in AZ B
resource "aws_subnet" "private_b" {
  vpc_id            = "vpc-0549027f59f08d65c"
  cidr_block        = "172.30.5.0/24"
  availability_zone = "ap-southeast-2b"

  tags = {
    Name = "any-api-private-subnet-b"
  }
}

# Route table for the private subnets
resource "aws_route_table" "private" {
  vpc_id = "vpc-0549027f59f08d65c"

  tags = {
    Name = "any-api-private-route-table"
  }
}

# Associate private subnet A with the private route table
resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

# Associate private subnet B with the private route table
resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_lb" "any_api_alb" {
  name               = "any-api-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.any_api_alb_sg.id]
  subnets            = ["subnet-0454b13ef9076a7e1", "subnet-0e175c6eb8916ef25"]
}

resource "aws_lb_target_group" "any_api_backend_tg" {
  name        = "any-api-backend-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = "vpc-0549027f59f08d65c"
  target_type = "instance"

  health_check {
    path                = "/hello"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group_attachment" "any_api_backend_tg_attachment" {
  target_group_arn = aws_lb_target_group.any_api_backend_tg.arn
  target_id        = aws_instance.any_api_backend_server.id
  port             = 8080
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.any_api_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.any_api_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = "arn:aws:acm:ap-southeast-2:293875060805:certificate/c1213248-fb2e-4387-9b4d-4ff31c74ff0d"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.any_api_backend_tg.arn
  }
}

# Security Groups
resource "aws_security_group" "any_api_alb_sg" {
  name        = "any-api-alb-sg"
  description = "loan balancing security group"
  vpc_id      = "vpc-0549027f59f08d65c"
}

resource "aws_security_group_rule" "any_api_alb_sg_ingress_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.any_api_alb_sg.id
}

resource "aws_security_group_rule" "any_api_alb_sg_ingress_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.any_api_alb_sg.id
}

resource "aws_security_group_rule" "any_api_alb_sg_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.any_api_alb_sg.id
}

resource "aws_security_group" "any_api_rds_sg" {
  name        = "any-api-rds-sg"
  description = "Created by RDS management console"
  vpc_id      = "vpc-0549027f59f08d65c"
}

resource "aws_security_group_rule" "any_api_rds_sg_ingress_postgres" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.any_api_backend_sg.id
  security_group_id        = aws_security_group.any_api_rds_sg.id
}

resource "aws_security_group_rule" "any_api_rds_sg_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.any_api_rds_sg.id
}

resource "aws_security_group" "any_api_backend_sg" {
  name        = "any-api-backend-sg"
  description = "Security group for Any-API Backend Server"
  vpc_id      = "vpc-0549027f59f08d65c"
}

resource "aws_security_group_rule" "any_api_backend_sg_ingress_http" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.any_api_alb_sg.id
  security_group_id        = aws_security_group.any_api_backend_sg.id
}

resource "aws_security_group_rule" "any_api_backend_sg_ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["49.49.224.178/32"]
  security_group_id = aws_security_group.any_api_backend_sg.id
}

resource "aws_security_group_rule" "any_api_backend_sg_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.any_api_backend_sg.id
}