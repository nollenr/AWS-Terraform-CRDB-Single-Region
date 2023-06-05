# output "subnets" {
#   description = "Subnets"
#   value = local.subnet_list[*]
# }

# output "private_subnet_list" {
#   description = "private subnets"
#   value = local.private_subnet_list
# }

# output "public_subnet_list" {
#   description = "public subnets"
#   value = local.public_subnet_list
# }

# output "availability_zones" {
#   description = "availability zones"
#   value = data.aws_availability_zones.available.names
# }

# output "availability_zone_list" {
#   description = "availability zone list"
#   value = local.availability_zone_list
# }

# output "igw_id" {
#   description = "internet gateway id"
#   value       = module.vpc.igw_id
# }

# output "public_route_table_ids" {
#   description = "list of public route tables"
#   value       = module.vpc.public_route_table_ids
# }

# output "private_route_table_ids" {
#   description = "list of public route tables"
#   value       = module.vpc.private_route_table_ids
# }

# output "vpc_id" {
#   description = "VPC ID"
#   value       = module.vpc.vpc_id
# }

# output "network_interfaces" {
#   description = "List of network interfaces"
#   value       = aws_network_interface.crdb[*].private_ip
# }

# output "haproxy_ip" {
#   description = "HA Proxy Private IP"
#   value       = aws_network_interface.haproxy[0].private_ip
# }

# ----------------------------------------
# Output Required for Use of multi-cloud
# These values are needed for additional
# nodes of the cluster.
# ---------------------------------------- 
output "ca_key" {
    description = "ca.key / tls_private_key"
    value = tls_private_key.crdb_ca_keys.private_key_pem
    sensitive = true
}
output "ca_pub" {
    description = "ca.pub / tls_public_key"
    value = tls_private_key.crdb_ca_keys.public_key_pem
    sensitive = true
}
output "ca_crt" {
    description = "ca.crt / tls_cert"
    value = tls_self_signed_cert.crdb_ca_cert.cert_pem
    sensitive = true
}
output "client_name_crt" {
    description = "client.name.crt / tls_user_cert"
    value = tls_locally_signed_cert.user_cert.cert_pem
    sensitive = true
}
output "client_name_key" {
    description = "client.name.crt / tls_user_key"
    value = tls_private_key.client_keys.private_key_pem
    sensitive = true
}
output "join_string" {
    description = "CRDB Startup Join String - For joining additional nodes to an existing cluster"
    value = module.crdb-region-0.join_string
}
output "join_string_public"{
    description = "CRDB Startup Join String Public - For joining additional nodes to an existing cluster using public IPs (multi-cloud)"
    value = module.crdb-region-0.join_string_public
}