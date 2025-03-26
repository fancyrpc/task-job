# Production-ready Kubernetes Cluster on AWS

## Тестовое задание
    - Управляемым кластером EKS
    - Автомасштабированием рабочих nodes
    - Автомасштабированием подов nginx
    - Публичным доступом через Load Balancer
    - Автоматическим обновлением дополнений EKS
    - Автоматическим обновлением узлов EKS
    - Автоматическим обновлением pods NGINX без down time

## Основные компоненты:  
- VPC
- Subnets
- Security Groups
- Route Tables
- NAT Gateway
- Load Balancer
- AWS EKS
- Karpenter
- NGINX
- CloudWatch
- IAM
- S3
- ECR
- EKS Addons
- OIDC
- IRSA
- Kube Proxy
- CoreDNS
- EBS CSI
- ALB Ingress Controller

## Кластер должен соответствовать следующим требованиям чек-лиcта:
### Безопасность:
    - Включить логирование control plane EKS
    - Реализовать Network Policies
    - Включить шифрование EBS
    - Регулярно ротировать IAM-ключи

### Надежность:
    - Развернуть в 3+ зонах доступности (AZ)
    - Настроить requests/limits для подов
    - Реализовать Pod Disruption Budgets
    - Affinity/Anti-Affinity

### Мониторинг:
    - Настроить CloudWatch-алерты
    - Настроить health checks

### Обслуживание:
    - Включить автообновление нод
    - Настроить политику обновлений Kubernetes

### Масштабируемость:
    - Настроить Karpenter
    - HPA + KEDA