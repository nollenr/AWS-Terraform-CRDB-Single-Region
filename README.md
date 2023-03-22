AWS Terraform - CockroachDB on EC2
==================================

## The Terraform script creates the following infrastructure:
* tls private database keys
* self-signed cert (ca.crt) for tsl connections to the database
* tls private client keys (optional)
* tls client cert request (optional)
* tls locally signed cert for client database access (optional)
* VPC (Virtual Private Cloud)
* IGW (Internet Gateway associated with the VPC)
* public (3) and private (3) subnets
* route tables (public & private)
* Security group for intra-node access
* Security group for a specific IP (from variable `my_ip_address`) with access for SSH, RDP, HTTP (8080), and Database on 26257
* Database Instances (number of instances is configurable via a variable)
* HA Proxy (optional) -- if the HA Proxy is created, it is configured to access the database instances
* APP Node (optional) -- if the APP node is created, a function is created (CRDB) which will connect to the database via haproxy using client certs

![Visual Description of the Terraform Script Output](/Resources/cloud_formation_VPC_output.drawio.png)


## Variables
### Variables available in terraform.tfvars 
* `my_ip_address` = "The IP address of the user running this script.  This is used to configure the a security group with access to SSH, RDP, HTTP and Database ports in all public instances."
* `aws_region_01` = "AWS Region to create the objects"
* `owner` = "A tag is placed on all resources created by this Terraform script.  Tag is (owner: "owner")"
* `crdb_nodes` = Number of CockroachDB Nodes to create.  The number should be a multiple of 3.  The script will use 3 AZs and place equal number of nodes in each AZ.  
* `crdb_instance_type` = "The instance type to choose for the CockroachDB nodes.  NOTE:  There is a condition on this variable in variables.tf."
* `crdb_root_volume_type` = "storage type for the CRDB root volume.  Usual values are 'gp2' or gp3'"
* `crdb_root_volume_size` = The size in GB for the root volume attached to the CRDB nodes.  
* `run_init` = "yes or no -- should the 'cockroach init' command be issued after the nodes are created?"
* `include_ha_proxy` = "yes or no - should an HA Proxy node be created and configured."
* `haproxy_instance_type` = "The instance type to choose for the HA Proxy node."
* `include_app` = "yes or no - should an app node be included?"
* `app_instance_type` = "The instance type to choose for the APP Node"
* `crdb_instance_key_name` = "The name of the AWS Key to use for all instances created by this Terraform Script.  This must be an existing Key for the region selected."
* `create_admin_user` = "yes or no - should an admin user (with cert) be creawted for this datagbase"
* `admin_user_name` = "Username of the admin user"

### Variables available in variables.tf
  In addition to the variables listed above, the following variables are also avialable
* `project_name`    =  Name of the project.
* `environment`     =  Name of the environment.
* `owner`           =  Owner of the infrastructure
* `resource_tags`   =  Tags to set for all resources
* `vpc_cidr`        =  CIDR block for the VPC
* `crdb_version`    =  CockroachDB Version  Note:  There is a condition on this field -- only values in the conditional statement will be allowed.

## Running the Terraform Script
### Install Terraform
I run the script from a small app server running AWS Linux 2 in any AWS region -- the app server does not need to be the region where the resources will be created.  I use a t3a.micro instance in us-west-2.
```terraform
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
```

### Generate AWS Access Key and Secret Security Credentials
The user behind the security credentials will need permissions to create each of the resources listed above.   

### Run this Terraform Script
```terraform
export AWS_ACCESS_KEY_ID={ID}
export AWS_SECRET_ACCESS_KEY={SECRET}
terraform fmt (optinal)
terraform validate
terraform plan
terraform apply
```

## Files in this repo
* `terraform.tf` Sets the AWS provider and versions
* `variables.tf` Creates the variables, definitions and defaults
* `terraform.tfvars` Easy access to variable values (without having to change the default value in `variables.tf`)
* `main.tf` Defines and creates the AWS resources
* `outputs.tf` Defines the outputs from the script.  These are variables which are referencable in `terraform console`
