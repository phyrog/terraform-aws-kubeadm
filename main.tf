terraform {
  required_version = ">= 0.12"
}

provider "aws" {
  region = "eu-central-1"
}

#------------------------------------------------------------------------------#
# Common local values
#------------------------------------------------------------------------------#

resource "random_pet" "cluster_name" {}

data "aws_region" "current" {}

data "aws_vpc" "current" {
  id = var.vpc_id
}

locals {
  cluster_name = var.cluster_name != null ? var.cluster_name : random_pet.cluster_name.id
  tags         = merge(var.tags, { "terraform-kubeadm:cluster" = local.cluster_name, "kubernetes.io/cluster/${local.cluster_name}" = "owned" })
  subnet_tags  = { "kubernetes.io/cluster/${local.cluster_name}" = "shared" }
  install_count = var.install_kubernetes ? 1 : 0
}

#------------------------------------------------------------------------------#
# Key pair
#------------------------------------------------------------------------------#

# Performs 'ImportKeyPair' API operation (not 'CreateKeyPair')
resource "aws_key_pair" "main" {
  key_name_prefix = "${local.cluster_name}-"
  public_key      = file(var.public_key_file)
  tags            = local.tags
}

#------------------------------------------------------------------------------#
# Master Instance Profile
#------------------------------------------------------------------------------#

resource "aws_iam_role" "master" {
  name = "${local.cluster_name}-master"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Effect = "Allow"
      Sid = ""
    }]
  })
}

resource "aws_iam_role_policy" "master" {
  name = "${local.cluster_name}-master"
  role = aws_iam_role.master.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action: [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeTags",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyVolume",
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteVolume",
        "ec2:DetachVolume",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeVpcs",
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:AttachLoadBalancerToSubnets",
        "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
        "elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:CreateLoadBalancerPolicy",
        "elasticloadbalancing:CreateLoadBalancerListeners",
        "elasticloadbalancing:ConfigureHealthCheck",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:DeleteLoadBalancerListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DetachLoadBalancerFromSubnets",
        "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
        "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:CreateTargetGroup",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:DeleteTargetGroup",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerPolicies",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:ModifyTargetGroup",
        "elasticloadbalancing:RegisterTargets",
        "elasticloadbalancing:DeregisterTargets",
        "elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
        "iam:CreateServiceLinkedRole",
        "kms:DescribeKey"
      ]
      Effect: "Allow"
      Resource: "*"
    }]
  })
}

resource "aws_iam_instance_profile" "master" {
  name = "${local.cluster_name}-master"
  role = aws_iam_role.master.name
}

#------------------------------------------------------------------------------#
# Worker Instance Profile
#------------------------------------------------------------------------------#

resource "aws_iam_role" "worker" {
  name = "${local.cluster_name}-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Effect = "Allow"
      Sid = ""
    }]
  })
}

resource "aws_iam_role_policy" "worker" {
  name = "${local.cluster_name}-worker"
  role = aws_iam_role.worker.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action: [
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ]
      Effect: "Allow"
      Resource: "*"
    }]
  })
}

resource "aws_iam_instance_profile" "worker" {
  name = "${local.cluster_name}-worker"
  role = aws_iam_role.worker.name
}

#------------------------------------------------------------------------------#
# Security groups
#------------------------------------------------------------------------------#

resource "aws_security_group" "master" {
  name = "${local.cluster_name}-master"
  description = "Master node security group"
  vpc_id = var.vpc_id
  tags = local.tags
}

resource "aws_security_group" "worker" {
  name = "${local.cluster_name}-worker"
  description = "Worker node security group"
  vpc_id = var.vpc_id
  tags = local.tags
}

locals {
  security_group_ids = [aws_security_group.master.id, aws_security_group.worker.id]
  sg_combinations = setproduct(local.security_group_ids, local.security_group_ids)
}

# The AWS provider removes the default "allow all "egress rule from all security
# groups, so it has to be defined explicitly.
resource "aws_security_group_rule" "node_egress" {
  count = length(local.security_group_ids)

  type        = "egress"
  protocol    = -1
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = local.security_group_ids[count.index]
}

resource "aws_security_group_rule" "node_ingress_ssh" {
  count = length(local.security_group_ids)

  type        = "ingress"
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  cidr_blocks = var.allowed_ssh_cidr_blocks
  security_group_id = local.security_group_ids[count.index]
}

resource "aws_security_group_rule" "node_ingress_30080" {
  count = length(local.security_group_ids)

  type        = "ingress"
  protocol    = "tcp"
  from_port   = 30080
  to_port     = 30080
  cidr_blocks = var.allowed_ssh_cidr_blocks
  security_group_id = local.security_group_ids[count.index]
}

resource "aws_security_group_rule" "master_ingress_api" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = 6443
  to_port     = 6443
  cidr_blocks = var.allowed_k8s_cidr_blocks
  security_group_id = aws_security_group.master.id
}

resource "aws_security_group_rule" "ingress_internal" {
  count = length(local.sg_combinations)

  type        = "ingress"
  protocol    = -1
  from_port   = 0
  to_port     = 0
  source_security_group_id = local.sg_combinations[count.index][0]
  security_group_id = local.sg_combinations[count.index][1]
}

#------------------------------------------------------------------------------#
# Elastic IP for master node
#------------------------------------------------------------------------------#

# EIP for master node because it must know its public IP during initialisation
resource "aws_eip" "master" {
  vpc  = true
  tags = local.tags
}

resource "aws_eip_association" "master" {
  allocation_id = aws_eip.master.id
  instance_id   = aws_instance.master.id
}

#------------------------------------------------------------------------------#
# Bootstrap token for kubeadm
#------------------------------------------------------------------------------#

# Generate bootstrap token
# See https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/
resource "random_string" "token_id" {
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "token_secret" {
  length  = 16
  special = false
  upper   = false
}

locals {
  token = "${random_string.token_id.result}.${random_string.token_secret.result}"
}

#------------------------------------------------------------------------------#
# EC2 instances
#------------------------------------------------------------------------------#

data "aws_ami" "ubuntu" {
  owners      = ["099720109477"] # AWS account ID of Canonical
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }
}

resource "aws_instance" "master" {
  ami                   = data.aws_ami.ubuntu.image_id
  instance_type         = var.master_instance_type
  iam_instance_profile  = aws_iam_instance_profile.master.name
  subnet_id             = var.subnet_id
  key_name              = aws_key_pair.main.key_name
  vpc_security_group_ids = [
    aws_security_group.master.id
  ]
  tags      = merge(local.tags, { "terraform-kubeadm:node" = "master", "Name" = "${local.cluster_name}-master" })
  user_data = <<-EOF
#!/bin/bash

# Install kubeadm and Docker
apt-get update
apt-get install -y apt-transport-https curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" >/etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y docker.io kubeadm

%{if var.install_kubernetes~}

# Create kubeadm config file
HOSTNAME=$(hostname)
INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
cat > ./kubeadm-init.conf <<CONFIG
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
bootstrapTokens:
- token: "${local.token}"
  ttl: 15m
nodeRegistration:
  name: $${HOSTNAME}.${data.aws_region.current.name}.compute.internal
  kubeletExtraArgs:
    cloud-provider: aws
    provider-id: $${INSTANCE_ID}
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
clusterName: "${local.cluster_name}"
controllerManager:
  extraArgs:
    cloud-provider: aws
    configure-cloud-routes: "false"
    address: 0.0.0.0
apiServer:
  extraArgs:
    cloud-provider: aws
  certSANs:
  - "${aws_eip.master.public_ip}"
networking:
%{if var.pod_network_cidr_block != null~}
  podSubnet: "${var.pod_network_cidr_block}"
%{endif~}
CONFIG

# Run kubeadm
kubeadm init --config ./kubeadm-init.conf

# Prepare kubeconfig file for download to local machine
cp /etc/kubernetes/admin.conf /home/ubuntu
chown ubuntu:ubuntu /home/ubuntu/admin.conf
kubectl --kubeconfig /home/ubuntu/admin.conf config set-cluster ${local.cluster_name} --server https://${aws_eip.master.public_ip}:6443

# Indicate completion of bootstrapping on this node
touch /home/ubuntu/done
%{endif~}
EOF
}

resource "aws_instance" "workers" {
  count                       = var.num_workers
  ami                         = data.aws_ami.ubuntu.image_id
  instance_type               = var.worker_instance_type
  iam_instance_profile        = aws_iam_instance_profile.worker.name
  subnet_id                   = var.subnet_id
  associate_public_ip_address = true
  key_name                    = aws_key_pair.main.key_name
  vpc_security_group_ids = [
    aws_security_group.worker.id
  ]
  tags      = merge(local.tags, { "terraform-kubeadm:node" = "worker-${count.index}", "Name" = "${local.cluster_name}-worker-${count.index}" })
  user_data = <<-EOF
#!/bin/bash

# Install kubeadm and Docker
apt-get update
apt-get install -y apt-transport-https curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" >/etc/apt/sources.list.d/kubernetes.list
apt-get update
apt-get install -y docker.io kubeadm

%{if var.install_kubernetes~}
# Run kubeadm
HOSTNAME=$(hostname)
INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
cat > kubeadm-join.conf <<CONFIG
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: ${aws_instance.master.private_ip}:6443
    token: "${local.token}"
    unsafeSkipCAVerification: true
  timeout: 5m0s
nodeRegistration:
  name: $${HOSTNAME}.${data.aws_region.current.name}.compute.internal
  kubeletExtraArgs:
    cloud-provider: aws
    provider-id: $${INSTANCE_ID}
CONFIG

kubeadm join ${aws_instance.master.private_ip}:6443 --config ./kubeadm-join.conf

# Indicate completion of bootstrapping on this node
touch /home/ubuntu/done
%{endif~}
EOF
}

#------------------------------------------------------------------------------#
# Wait for bootstrap to finish on all nodes
#------------------------------------------------------------------------------#

resource "null_resource" "wait_for_bootstrap_to_finish" {

  count = local.install_count

  provisioner "local-exec" {
    command = <<-EOF
    alias ssh='ssh -q -i ${var.private_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    while true; do
      sleep 2
      ! ssh ubuntu@${aws_eip.master.public_ip} [[ -f /home/ubuntu/done ]] >/dev/null && continue
      %{for worker_public_ip in aws_instance.workers[*].public_ip~}
      ! ssh ubuntu@${worker_public_ip} [[ -f /home/ubuntu/done ]] >/dev/null && continue
      %{endfor~}
      break
    done
    EOF
  }
  triggers = {
    instance_ids = join(",", concat([aws_instance.master.id], aws_instance.workers[*].id))
  }
}

#------------------------------------------------------------------------------#
# Tag all subnets with cluster specific tags
#------------------------------------------------------------------------------#

locals {
  subnet_ids = distinct(concat([aws_instance.master.subnet_id], aws_instance.workers.*.subnet_id))
  joined_tags_list = [
    for tag in keys(local.subnet_tags):
    "Key=${tag},Value=${local.subnet_tags[tag]}"
  ]
  joined_tags = join(" ", local.joined_tags_list)
  joined_subnet_ids = join(" ", local.subnet_ids)
}

resource "null_resource" "subnet_tags" {
  provisioner "local-exec" {
    command = <<-EOF
    alias aws="AWS_REGION=${self.triggers.region} aws"
    aws ec2 create-tags --resources ${self.triggers.subnet_ids} --tags ${self.triggers.tags}
    EOF
  }

  provisioner "local-exec" {
    when = destroy
    command = <<-EOF
    alias aws="AWS_REGION=${self.triggers.region} aws"
    aws ec2 delete-tags --resources ${self.triggers.subnet_ids} --tags ${self.triggers.tags}
    EOF
  }

  triggers = {
    region = data.aws_region.current.name
    subnet_ids = local.joined_subnet_ids
    tags = local.joined_tags
    wait_for_bootstrap_to_finish = null_resource.wait_for_bootstrap_to_finish[0].id
  }
}
#------------------------------------------------------------------------------#
# Download kubeconfig file from master node to local machine
#------------------------------------------------------------------------------#

locals {
  kubeconfig_file = var.kubeconfig_file != null ? abspath(pathexpand(var.kubeconfig_file)) : "${abspath(pathexpand(var.kubeconfig_dir))}/kube.conf"
}

resource "null_resource" "download_kubeconfig_file" {

  count = local.install_count

  provisioner "local-exec" {
    command = <<-EOF
    alias scp='scp -q -i ${var.private_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    scp ubuntu@${aws_eip.master.public_ip}:/home/ubuntu/admin.conf ${local.kubeconfig_file} >/dev/null
    EOF
  }

  triggers = {
    wait_for_bootstrap_to_finish = null_resource.wait_for_bootstrap_to_finish[0].id
  }
}

#------------------------------------------------------------------------------#
# Install Flannel as overlay network
#------------------------------------------------------------------------------#

resource "null_resource" "install_flannel" {

  count = local.install_count

  provisioner "local-exec" {
    command = <<-EOF
    alias kubectl='KUBECONFIG=${self.triggers.kubeconfig_file} kubectl'
    kubectl apply -f flannel.yaml
    EOF
  }

  triggers = {
    kubeconfig_file = local.kubeconfig_file
    download_kubeconfig_file = null_resource.download_kubeconfig_file[0].id
  }
}
