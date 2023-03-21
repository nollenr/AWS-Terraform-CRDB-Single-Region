provider "aws" {
  region = var.aws_region_01
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon-linux-2" {
 most_recent = true
 owners = ["amazon"]
 filter {
   name   = "name"
   values = ["amzn2-ami-hvm*"]
 }
}

locals {
  required_tags = {
    owner       = var.owner,
    project     = var.project_name,
    environment = var.environment
  }
  tags = merge(var.resource_tags, local.required_tags)
  
  # create 6 subnets: 3 for public subnets, 3 for private subnets
  subnet_list = cidrsubnets(var.vpc_cidr,3,3,3,3,3,3)

  private_subnet_list = chunklist(local.subnet_list,3)[0]
  public_subnet_list  = chunklist(local.subnet_list,3)[1]

  availability_zone_count = 3

  availability_zone_list = slice(data.aws_availability_zones.available.names,0,local.availability_zone_count)

}

locals {
  depends_on = [aws_network_interface.crdb]
  ip_list     = join(" ", aws_network_interface.crdb[*].private_ip)
  join_string = join(",", aws_network_interface.crdb[*].private_ip)
}

resource "random_id" "id" {
  byte_length = 8
}

# -----------------------------------------------------------------------
#  CRDB Keys and ca.crt
# -----------------------------------------------------------------------
# Create both the keys and cert required for secure mode
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key#private_key_openssh
resource "tls_private_key" "crdb_ca_keys" {
  algorithm = "RSA"
  rsa_bits  = 2048 
}

# https://www.cockroachlabs.com/docs/v22.2/create-security-certificates-openssl
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/self_signed_cert
# also created cert with : su - ec2-user -c 'openssl req -new -x509 -key my-safe-directory/ca.key -out certs/ca.crt -days 1831 -subj "/O=Cockroach /CN=Cockroach CA /keyUsage=critical,digitalSignature,keyEncipherment /extendedKeyUsage=clientAuth"'
resource "tls_self_signed_cert" "crdb_ca_cert" {
  private_key_pem = tls_private_key.crdb_ca_keys.private_key_pem

  subject {
    common_name  = "Cockroach CA"
    organization = "Cockroach"
  }

  validity_period_hours = 43921
  is_ca_certificate = true

  allowed_uses = [
    "any_extended",
    "cert_signing",
    "client_auth",
    "code_signing",
    "content_commitment",
    "crl_signing",
    "data_encipherment",
    "digital_signature",
    "email_protection",
    "key_agreement",
    "key_encipherment",
    "ocsp_signing",
    "server_auth"
  ]
}

# -----------------------------------------------------------------------
# Client Keys and cert
# -----------------------------------------------------------------------
# https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key#private_key_openssh
resource "tls_private_key" "client_keys" {
  algorithm = "RSA"
  rsa_bits  = 2048 
}

resource "tls_cert_request" "client_csr" {
  private_key_pem = tls_private_key.client_keys.private_key_pem

  subject {
    organization = "Cockroach"
    common_name = "ron"
  }

  dns_names = ["root"]

}

resource "tls_locally_signed_cert" "user_cert" {
  cert_request_pem = tls_cert_request.client_csr.cert_request_pem
  ca_private_key_pem = tls_private_key.crdb_ca_keys.private_key_pem
  ca_cert_pem = tls_self_signed_cert.crdb_ca_cert.cert_pem

  validity_period_hours = 43921

    allowed_uses = [
    "any_extended",
    "cert_signing",
    "client_auth",
    "code_signing",
    "content_commitment",
    "crl_signing",
    "data_encipherment",
    "digital_signature",
    "email_protection",
    "key_agreement",
    "key_encipherment",
    "ocsp_signing",
    "server_auth"
  ]
}

# create the vpc, igw, public and private subnets, route tables 
# 3 private route tables are created and include /24 routes (the entire vpc)
# public route inlcudes igw and local /24 routes (the entire vpc)
module "vpc" {
  #  https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  create_database_subnet_group = false
  create_egress_only_igw = false
  create_elasticache_subnet_group = false
  create_igw = true
  enable_dns_hostnames = true
  enable_dns_support = true

  azs = local.availability_zone_list
  cidr = var.vpc_cidr
  private_subnets = local.private_subnet_list
  public_subnets = local.public_subnet_list

  tags = local.tags
}

# https://registry.terraform.io/modules/terraform-aws-modules/security-group/aws/latest#input_ingress_with_self
# https://github.com/terraform-aws-modules/terraform-aws-security-group/blob/master/examples/complete/main.tf
module "security-group-01" {
  # https://registry.terraform.io/modules/terraform-aws-modules/security-group/aws/latest
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.17.1"

  depends_on = [module.vpc]

  name = "sg01"
  description = "Allow desktop access (SSH, RDP, Database, HTTP) to EC2 instances"
  tags = local.tags

  # ingress_cidr_blocks = ["var.my_ip_address/32"]
  ingress_cidr_blocks = ["${var.my_ip_address}/32"]
  ingress_with_cidr_blocks = [
    {
      from_port   = 26257
      to_port     = 26257
      protocol    = "tcp"
      description = "Allow cockroach database access from my-ip"
    },
    { rule = "ssh-tcp" },
    { rule = "http-8080-tcp" },
    { rule="rdp-tcp" },
    { rule="rdp-udp" }

  ]
  egress_rules = ["all-all"]
  vpc_id = module.vpc.vpc_id
}

module "security-group-02" {
  # https://registry.terraform.io/modules/terraform-aws-modules/security-group/aws/latest
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.17.1"

  depends_on = [
    module.vpc
  ]

  name = "sg02"
  description = "Allow Intra-node communication"
  tags = local.tags

  # This creates a rule to allow all ingress on all ports of all types for anything in this security group
  ingress_with_self = [{rule = "all-all"}]
  # This creates a rule to allow all egress 
  egress_rules = ["all-all"]
  vpc_id = module.vpc.vpc_id
}

# AWS Network Interfaces - 1 Per CRDB Node
# I need all of the private IP addresses before creating the nodes
# so that I can assemble the join string and set up ssh between the nodes
resource "aws_network_interface" "crdb" {
  depends_on = [
    module.vpc
  ]
  tags = local.tags
  count                 = var.crdb_nodes
  subnet_id             = "${element(module.vpc.public_subnets , count.index)}"
  # when creating network interfaces, the security group must go here, not in the instance config
  security_groups = [module.security-group-02.security_group_id, module.security-group-01.security_group_id]
}

# Always create the haproxy network interface, even if it is not going to be used.
# This is required for adding the ip address to the node cert.  The code that adds
# the node cert, cannot know if the haproxy is required or not.
resource "aws_network_interface" "haproxy" {
  depends_on = [
    module.vpc
  ]
  tags = local.tags
  count                 = 1
  subnet_id             = "${element(module.vpc.public_subnets , count.index)}"
  # when creating network interfaces, the security group must go here, not in the instance config
  security_groups = [module.security-group-02.security_group_id, module.security-group-01.security_group_id]
}


# CRDB Nodes
resource "aws_instance" "crdb" {
  count         = var.crdb_nodes
  depends_on = [
    aws_network_interface.crdb,
    aws_network_interface.haproxy,
    module.security-group-02,
    module.security-group-01,
    module.vpc
  ]
  user_data_replace_on_change = true
  tags = merge(local.tags, {Name = "${var.owner}-crdb-instance-${count.index}"})
  ami           = "${data.aws_ami.amazon-linux-2.id}"
  instance_type = var.crdb_instance_type
  network_interface {
    network_interface_id = aws_network_interface.crdb[count.index].id
    device_index = 0
  }
  key_name      = var.crdb_instance_key_name
  root_block_device {
    delete_on_termination = true
    encrypted = true
    volume_type = var.crdb_root_volume_type
    volume_size = var.crdb_root_volume_size
  }
  user_data = <<EOF
    #!/bin/bash -xe
    echo "Setting variables"
    echo "export COCKROACH_CERTS_DIR=/home/ec2-user/certs" >> /home/ec2-user/.bashrc
    echo 'export CLUSTER_PRIVATE_IP_LIST="${local.ip_list}" ' >> /home/ec2-user/.bashrc
    echo 'export JOIN_STRING="${local.join_string}" ' >> /home/ec2-user/.bashrc
    echo "export ip_local=\`curl http://169.254.169.254/latest/meta-data/local-ipv4\`" >> /home/ec2-user/.bashrc
    echo "export ip_public=\`curl http://169.254.169.254/latest/meta-data/public-ipv4\`" >> /home/ec2-user/.bashrc
    echo "export aws_region=\`curl http://169.254.169.254/latest/meta-data/placement/region\`" >> /home/ec2-user/.bashrc
    echo "export aws_az=\`curl http://169.254.169.254/latest/meta-data/placement/availability-zone\`" >> /home/ec2-user/.bashrc
    export CLUSTER_PRIVATE_IP_LIST="${local.ip_list}"
    echo "export CRDBNODE=${count.index}" >> /home/ec2-user/.bashrc
    export CRDBNODE=${count.index}
    counter=1;for IP in $CLUSTER_PRIVATE_IP_LIST; do echo "export NODE$counter=$IP" >> /home/ec2-user/.bashrc; (( counter++ )); done

    echo "Downloading and installing CockroachDB along with the Geo binaries"
    curl https://binaries.cockroachdb.com/cockroach-v${var.crdb_version}.linux-amd64.tgz | tar -xz && cp -i cockroach-v${var.crdb_version}.linux-amd64/cockroach /usr/local/bin/
    mkdir -p /usr/local/lib/cockroach
    cp -i cockroach-v${var.crdb_version}.linux-amd64/lib/libgeos.so /usr/local/lib/cockroach/
    cp -i cockroach-v${var.crdb_version}.linux-amd64/lib/libgeos_c.so /usr/local/lib/cockroach/

    echo "Creating the public and private keys"
    su ec2-user -c 'mkdir /home/ec2-user/certs; mkdir /home/ec2-user/my-safe-directory'
    echo '${tls_private_key.crdb_ca_keys.private_key_pem}' >> /home/ec2-user/my-safe-directory/ca.key
    echo '${tls_private_key.crdb_ca_keys.public_key_pem}' >> /home/ec2-user/certs/ca.pub
    echo '${tls_self_signed_cert.crdb_ca_cert.cert_pem}' >> /home/ec2-user/certs/ca.crt

    echo "Changing ownership on permissions on keys and certs"
    chown ec2-user:ec2-user /home/ec2-user/certs/ca.crt
    chown ec2-user:ec2-user /home/ec2-user/certs/ca.pub
    chown ec2-user:ec2-user /home/ec2-user/my-safe-directory/ca.key
    chmod 640 /home/ec2-user/certs/ca.crt
    chmod 640 /home/ec2-user/certs/ca.pub
    chmod 600 /home/ec2-user/my-safe-directory/ca.key     

    echo "Copying the ca.key to .ssh/id_rsa, generating the public key and adding it to authorized keys for passwordless ssh between nodes"
    cp /home/ec2-user/my-safe-directory/ca.key /home/ec2-user/.ssh/id_rsa
    ssh-keygen -y -f /home/ec2-user/.ssh/id_rsa >> /home/ec2-user/.ssh/authorized_keys

    echo "Creating the CREATENODECERT bashrc function"
    echo "CREATENODECERT() {" >> /home/ec2-user/.bashrc
    echo "  cockroach cert create-node \\" >> /home/ec2-user/.bashrc
    echo '  $ip_local \' >> /home/ec2-user/.bashrc
    echo '  $ip_public \' >> /home/ec2-user/.bashrc
    echo "  localhost \\" >> /home/ec2-user/.bashrc
    echo "  127.0.0.1 \\" >> /home/ec2-user/.bashrc
    echo "Adding haproxy to the CREATENODECERT function if var.include_ha_proxy is yes"
    if [ "${var.include_ha_proxy}" = "yes" ]; then echo "  ${aws_network_interface.haproxy[0].private_ip} \\" >> /home/ec2-user/.bashrc; fi
    echo "  --certs-dir=certs \\" >> /home/ec2-user/.bashrc
    echo "  --ca-key=my-safe-directory/ca.key" >> /home/ec2-user/.bashrc
    echo "}" >> /home/ec2-user/.bashrc

    echo "Creating the CREATEROOTCERT bashrc function"
    echo "CREATEROOTCERT() {" >> /home/ec2-user/.bashrc
    echo "  cockroach cert create-client \\" >> /home/ec2-user/.bashrc
    echo '  root \' >> /home/ec2-user/.bashrc
    echo "  --certs-dir=certs \\" >> /home/ec2-user/.bashrc
    echo "  --ca-key=my-safe-directory/ca.key" >> /home/ec2-user/.bashrc
    echo "}" >> /home/ec2-user/.bashrc   

    echo "Creating the STARTCRDB bashrc function"
    echo "STARTCRDB() {" >> /home/ec2-user/.bashrc
    echo "  cockroach start \\" >> /home/ec2-user/.bashrc
    echo '  --locality=region="$aws_region",zone="$aws_az" \' >> /home/ec2-user/.bashrc
    echo "  --certs-dir=certs \\" >> /home/ec2-user/.bashrc
    echo '  --advertise-addr=$ip_local \' >> /home/ec2-user/.bashrc
    echo '  --join=$JOIN_STRING \' >> /home/ec2-user/.bashrc
    echo '  --max-offset=250ms \' >> /home/ec2-user/.bashrc
    echo "  --background " >> /home/ec2-user/.bashrc
    echo " }" >> /home/ec2-user/.bashrc

    echo "Creating the node cert, root cert and starting CRDB"
    sleep 20; su ec2-user -lc 'CREATENODECERT; CREATEROOTCERT; STARTCRDB'

    echo "Validating if init needs to be run"
    echo "RunInit: ${var.run_init}  Count.Index: ${count.index}   Count: ${var.crdb_nodes}"
    if [[ '${var.run_init}' = 'yes' && ${count.index + 1} -eq ${var.crdb_nodes} ]]; then echo "Initializing Cockroach Database" && su ec2-user -lc 'cockroach init'; fi
    if [[ '${var.run_init}' = 'yes' && ${count.index + 1} -eq ${var.crdb_nodes} && ${var.create_admin_user} = 'yes' ]]; then echo "Creating admin user ${var.admin_user_name}" && su ec2-user -lc 'cockroach sql --execute "create user ${var.admin_user_name}; grant admin to ${var.admin_user_name}"'; fi
  EOF
}

# HAProxy Node
resource "aws_instance" "haproxy" {
  count         = var.include_ha_proxy == "yes" ? 1 : 0
  user_data_replace_on_change = true
  tags = merge(local.tags, {Name = "${var.owner}-crdb-haproxy-${count.index}"})
  ami           = "${data.aws_ami.amazon-linux-2.id}"
  instance_type = var.haproxy_instance_type
  key_name      = var.crdb_instance_key_name
  network_interface {
    network_interface_id = aws_network_interface.haproxy[count.index].id
    device_index = 0
  }
  root_block_device {
    delete_on_termination = true
    encrypted = true
    volume_type = "gp2"
    volume_size = 8
  }
  user_data = <<EOF
    #!/bin/bash -xe
    echo 'export CLUSTER_PRIVATE_IP_LIST="${local.ip_list}" ' >> /home/ec2-user/.bashrc
    export CLUSTER_PRIVATE_IP_LIST="${local.ip_list}"
    echo "HAProxy Config and Install"
    echo 'global' > /home/ec2-user/haproxy.cfg
    echo '  maxconn 4096' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo 'defaults' >> /home/ec2-user/haproxy.cfg
    echo '    mode                tcp' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo '    # Timeout values should be configured for your specific use.' >> /home/ec2-user/haproxy.cfg
    echo '    # See: https://cbonte.github.io/haproxy-dconv/1.8/configuration.html#4-timeout%20connect' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo '    # With the timeout connect 5 secs,' >> /home/ec2-user/haproxy.cfg
    echo '    # if the backend server is not responding, haproxy will make a total' >> /home/ec2-user/haproxy.cfg
    echo '    # of 3 connection attempts waiting 5s each time before giving up on the server,' >> /home/ec2-user/haproxy.cfg
    echo '    # for a total of 15 seconds.' >> /home/ec2-user/haproxy.cfg
    echo '    retries             2' >> /home/ec2-user/haproxy.cfg
    echo '    timeout connect     5s' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo '    # timeout client and server govern the maximum amount of time of TCP inactivity.' >> /home/ec2-user/haproxy.cfg
    echo '    # The server node may idle on a TCP connection either because it takes time to' >> /home/ec2-user/haproxy.cfg
    echo '    # execute a query before the first result set record is emitted, or in case of' >> /home/ec2-user/haproxy.cfg
    echo '    # some trouble on the server. So these timeout settings should be larger than the' >> /home/ec2-user/haproxy.cfg
    echo '    # time to execute the longest (most complex, under substantial concurrent workload)' >> /home/ec2-user/haproxy.cfg
    echo '    # query, yet not too large so truly failed connections are lingering too long' >> /home/ec2-user/haproxy.cfg
    echo '    # (resources associated with failed connections should be freed reasonably promptly).' >> /home/ec2-user/haproxy.cfg
    echo '    timeout client      10m' >> /home/ec2-user/haproxy.cfg
    echo '    timeout server      10m' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo '    # TCP keep-alive on client side. Server already enables them.' >> /home/ec2-user/haproxy.cfg
    echo '    option              clitcpka' >> /home/ec2-user/haproxy.cfg
    echo '' >> /home/ec2-user/haproxy.cfg
    echo 'listen psql' >> /home/ec2-user/haproxy.cfg
    echo '    bind :26257' >> /home/ec2-user/haproxy.cfg
    echo '    mode tcp' >> /home/ec2-user/haproxy.cfg
    echo '    balance roundrobin' >> /home/ec2-user/haproxy.cfg
    echo '    option httpchk GET /health?ready=1' >> /home/ec2-user/haproxy.cfg
    counter=1;for IP in $CLUSTER_PRIVATE_IP_LIST; do echo "    server cockroach$counter $IP:26257 check port 8080" >> /home/ec2-user/haproxy.cfg; (( counter++ )); done
    chown ec2-user:ec2-user /home/ec2-user/haproxy.cfg
    echo "Installing HAProxy"; yum -y install haproxy
    echo "Starting HAProxy as ec2-user"; su ec2-user -lc 'haproxy -f haproxy.cfg > haproxy.log 2>&1 &'
  EOF
}

resource "aws_instance" "app" {
  count                       = var.include_app == "yes" ? 1 : 0
  user_data_replace_on_change = true
  tags                        = merge(local.tags, {Name = "${var.owner}-crdb-app-${count.index}"})
  ami                         = "${data.aws_ami.amazon-linux-2.id}"
  instance_type               = var.app_instance_type
  key_name                    = var.crdb_instance_key_name
  subnet_id                   = "${element(module.vpc.public_subnets , count.index)}"
  security_groups             = [module.security-group-02.security_group_id, module.security-group-01.security_group_id]
  root_block_device {
    delete_on_termination = true
    encrypted = true
    volume_type = "gp2"
    volume_size = 8
  }
  #  To connect using the keys that have been created:
  #  cockroach-sql sql --url "postgres://192.168.4.103:26257/defaultdb?sslmode=verify-full&sslrootcert=$HOME/certs/ca.crt&sslcert=$HOME/certs/client.ron.crt&sslkey=$HOME/certs/client.ron.key"
  user_data = <<EOF
    #!/bin/bash -xe
    su ec2-user -c 'mkdir /home/ec2-user/certs'
    echo '${tls_self_signed_cert.crdb_ca_cert.cert_pem}' >> /home/ec2-user/certs/ca.crt 
    chown ec2-user:ec2-user /home/ec2-user/certs/ca.crt
    chmod 640 /home/ec2-user/certs/ca.crt
    echo '${tls_locally_signed_cert.user_cert.cert_pem}' >> /home/ec2-user/certs/client.${var.admin_user_name}.crt
    echo '${tls_private_key.client_keys.private_key_pem}' >> /home/ec2-user/certs/client.${var.admin_user_name}.key
    chown ec2-user:ec2-user /home/ec2-user/certs/client.ron.crt
    chmod 640 /home/ec2-user/certs/client.ron.crt

    echo "Downloading and installing CockroachDB along with the Geo binaries"
    curl https://binaries.cockroachdb.com/cockroach-sql-v${var.crdb_version}.linux-amd64.tgz | tar -xz && cp -i cockroach-sql-v${var.crdb_version}.linux-amd64/cockroach-sql /usr/local/bin/

    echo "CRDB() {" >> /home/ec2-user/.bashrc
    echo 'cockroach-sql sql --url "postgres://'"${aws_network_interface.haproxy[0].private_ip}:26257/defaultdb?sslmode=verify-full&sslrootcert="'$HOME/certs/ca.crt&sslcert=$HOME/certs/client.'"${var.admin_user_name}.crt&sslkey="'$HOME/certs/client.'"${var.admin_user_name}.key"'"' >> /home/ec2-user/.bashrc
    echo "}" >> /home/ec2-user/.bashrc   
  EOF
}

