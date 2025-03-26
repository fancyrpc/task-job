#####
# Группа безопасности CoreDNS
#####
resource "aws_security_group" "core_dns" {
  name_prefix = "${var.name_prefix}-coredns-sg-"
  description = "EKS CoreDNS security group."

  vpc_id = module.vpc_eks.vpc_id

  tags = {
    "Name"                                     = "${var.name_prefix}-coredns-sg"
    "kubernetes.io/cluster/${var.name_prefix}" = "owned"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# входящий трафик: разрешить доступ control plane EKS к CoreDNS
resource "aws_vpc_security_group_ingress_rule" "all_allow_access_from_control_plane_to_core_dns" {
  security_group_id = aws_security_group.core_dns.id
  description       = "разрешить доступ control plane EKS к CoreDNS"

  referenced_security_group_id = aws_eks_cluster.cluster.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "-1" # "-1" все протоколы
}

# входящий трафик: разрешить доступ от узлов Karpenter к CoreDNS
resource "aws_vpc_security_group_ingress_rule" "all_allow_access_from_karpenter_nodes_to_core_dns" {
  security_group_id = aws_security_group.core_dns.id
  description       = "разрешить доступ от узлов Karpenter к CoreDNS"

  referenced_security_group_id = aws_security_group.node.id
  ip_protocol                  = "-1" # "-1" означает все протоколы
}

# исходящий трафик: разрешить UDP трафик - DNS запросы
resource "aws_vpc_security_group_egress_rule" "core_dns_udp" {
  security_group_id = aws_security_group.core_dns.id
  description       = "Allow udp egress."

  from_port   = "53"
  to_port     = "53"
  ip_protocol = "udp"

  cidr_ipv4 = "0.0.0.0/0"
}

# исходящий трафик: TCP трафик для DNS запросов
resource "aws_vpc_security_group_egress_rule" "core_dns_tcp" {
  security_group_id = aws_security_group.core_dns.id
  description       = "Allow udp egress."

  from_port   = "53"
  to_port     = "53"
  ip_protocol = "tcp"

  cidr_ipv4 = "0.0.0.0/0"
}
