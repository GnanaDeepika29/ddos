# Outputs for Terraform AWS infrastructure

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "cluster_endpoint" {
  description = "Endpoint for EKS cluster"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = aws_eks_cluster.main.name
}

output "cluster_certificate_authority" {
  description = "Base64 encoded certificate data for EKS cluster"
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "node_group_id" {
  description = "ID of the EKS node group"
  value       = aws_eks_node_group.main.id
}

output "security_group_id" {
  description = "ID of the EKS cluster security group"
  value       = aws_security_group.eks_cluster.id
}