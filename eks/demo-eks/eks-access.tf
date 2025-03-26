data "aws_iam_group" "admins" {
  group_name = "Admins"
}

data "aws_iam_group" "devs" {
  group_name = "Devs"
}

locals {
  admins_arn = distinct([for user in data.aws_iam_group.admins.users : user.arn])
  devs_arn   = distinct([for user in data.aws_iam_group.devs.users : user.arn])
}

module "demo-admins-access-demo" {
  source = "../modules/eks-access"

  for_each = toset(local.admins_arn)

  iam_user_arn = each.value
  policy_name  = "AmazonEKSClusterAdminPolicy"
  cluster_name = "infra-demo"
  scope        = "cluster"

  depends_on = [module.demo-eks]
}

module "demo-devs-access-demo" {
  source = "../modules/eks-access"

  for_each = toset(local.devs_arn)

  iam_user_arn = each.value
  policy_name  = "AmazonEKSEditPolicy"
  cluster_name = "infra-demo"
  scope        = "namespace"
  namespaces   = ["demo"]
  cluster_view = true
  depends_on = [module.demo-eks]
}

module "dev-admins-access-demo" {
  source = "../modules/eks-access"

  for_each = toset(local.admins_arn)

  iam_user_arn = each.value
  policy_name  = "AmazonEKSClusterAdminPolicy"
  cluster_name = "infra-demo"
  scope        = "cluster"

  depends_on = [module.demo-eks]
}

module "dev-devs-access-demo" {
  source = "../modules/eks-access"

  for_each = toset(local.devs_arn)

  iam_user_arn = each.value
  policy_name  = "AmazonEKSEditPolicy"
  cluster_name = "infra-demo"
  scope        = "namespace"
  namespaces   = ["default" , "demo"]
  cluster_view = true
  depends_on = [module.demo-eks]
}
