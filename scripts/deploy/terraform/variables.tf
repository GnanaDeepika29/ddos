# Variables for Terraform AWS infrastructure

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones to use"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "ddos-defense-cluster"
}

variable "instance_types" {
  description = "EC2 instance types for node group"
  type        = list(string)
  default     = ["t3.medium", "t3.large"]
}

variable "min_capacity" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 2
}

variable "desired_capacity" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 3
}

variable "max_capacity" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 10
}

variable "admin_cidrs" {
  description = "CIDR blocks allowed for administrative access"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project     = "ddos-defense-platform"
    ManagedBy   = "Terraform"
  }
}