output "subnets" {
  description = "Subnets"
  value = local.subnet_list[*]
}

output "private_subnet_list" {
  description = "private subnets"
  value = local.private_subnet_list
}

output "public_subnet_list" {
  description = "public subnets"
  value = local.public_subnet_list
}

output "availability_zones" {
  description = "availability zones"
  value = data.aws_availability_zones.available.names
}

output "availability_zone_list" {
  description = "availability zone list"
  value = local.availability_zone_list
}

output "igw_id" {
  description = "internet gateway id"
  value       = module.vpc.igw_id
}

output "public_route_table_ids" {
  description = "list of public route tables"
  value       = module.vpc.public_route_table_ids
}

output "private_route_table_ids" {
  description = "list of public route tables"
  value       = module.vpc.private_route_table_ids
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "network_interfaces" {
  description = "List of network interfaces"
  value       = aws_network_interface.crdb[*].private_ip
}

output "haproxy_ip" {
  description = "HA Proxy Private IP"
  value       = aws_network_interface.haproxy[0].private_ip
}