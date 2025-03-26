module "demo-eks" {
  source = "../modules/eks"

  name_prefix = "infra-demo"

  vpc_cidr              = "10.43.0.0/16"
  private_subnets_cidrs = ["10.43.112.0/20", "10.43.128.0/20", "10.43.144.0/20"]
  public_subnets_cidrs  = ["10.43.0.0/20", "10.43.16.0/20", "10.43.32.0/20"]
  azs                   = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]

  eks_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  eks_service_ipv4_cidr = "10.190.0.0/16"

  instance_types = ["m6a.large"]
  desired_size   = 2

  eks_public_access_cidrs = [
    "0.0.0.0/0"
  ]

  eks_version = "1.30"

  eks_addon_version_kube_proxy     = "v1.30.0-eksbuild.3"
  eks_addon_version_core_dns       = "v1.11.1-eksbuild.9"
  eks_addon_version_ebs_csi_driver = "v1.31.0-eksbuild.1"
  eks_addon_version_guardduty = "v1.6.1-eksbuild.1"
  eks_addon_version_snapshot_controller = "v7.0.1-eksbuild.1"
  eks_addon_version_identity_agent      = "v1.2.0-eksbuild.1"

  default_tags = {
      Environment = "demo"
      Team        = "infra"
      Repository  = "https://github.com/fancyrpc/demo-eks-tasks.git"
      Service     = "eks"
  }
}
