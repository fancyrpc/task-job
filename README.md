# EKS Terraform

## Содержание

- [Описание](#описание)
- [Структура проекта](#структура-проекта)
- [Основные компоненты](#основные-компоненты)
- [Параметры Helm](#параметры-helm)
- [Описание модулей](#описание-модулей)
- [Архитектура](#архитектура)
- [RBAC](#rbac)
- [Ограничение сетевого доступа с NetworkPolicy](#ограничение-сетевого-доступа-с-networkpolicy)
- [NetworkPolicy](#networkpolicy)
- [Практики для NetworkPolicy](#практики-для-networkpolicy)
- [Пример использования с NGINX и KEDA](#пример-использования-с-nginx-и-keda)

## Описание

Данный Terraform модули для развертывания и управления кластером EKS. 
Модули включают настройку VPC, безопасности и addons EKS.


## Структура проекта

- **eks/demo-eks/** - Пример использования модулей
  - **main.tf** - Основная конфигурация Terraform
  - **eks.tf** - Конфигурация кластера EKS
  - **eks-access.tf** - Настройка доступа к кластеру
  - **outputs.tf** - Выходные параметры

## Описание модулей

### eks/modules/

#### eks-addon-coredns.tf
Модуль создает и настраивает инфраструктуру для CoreDNS — критически важного компонента Kubernetes, обеспечивающего разрешение DNS-имен внутри кластера:
- Создает отдельную группу безопасности для изоляции DNS-трафика
- Определяет правила для входящего трафика от плоскости управления EKS и узлов Karpenter
- Настраивает правила исходящего трафика для UDP и TCP на порту 53 (DNS)
- Применяет теги для интеграции с экосистемой Kubernetes

Отдельная группа безопасности для CoreDNS следует принципу наименьших привилегий и обеспечивает лучший контроль над сетевыми взаимодействиями.

#### data-vpce.tf
Настраивает VPC Endpoints для обеспечения безопасного доступа к сервисам AWS
- Создает интерфейсные (ENI) и шлюзовые (Gateway) эндпоинты для сервисов AWS
- Настраивает таблицы маршрутизации и политики доступа
- Приватная связь между кластером EKS и сервисами AWS (ECR, S3, CloudWatch ...)

Использование VPC Endpoints организует приватный трафик в сетях AWS, а также не платим за исходящий трафик.

#### cloudwatch.tf
Определяет ресурсы для мониторинга и логирования EKS-кластера:
- Создает группы логов для различных компонентов кластера
- Определяет метрики для отслеживания производительности кластера
- Настраивает алармы для оповещения о критических состояниях
- Конфигурирует политики хранения логов и метрик

#### variables.tf
Централизованное хранилище переменных для всех модулей:
- Определяет входные переменные с понятными именами и описаниями
- Устанавливает типы данных и значения по умолчанию
- Включает валидацию для предотвращения ошибок конфигурации
- Единый файл для настройки всех сеттингов кластера

#### userdata.tpl
Шаблон пользовательских данных (user data) для узлов EKS на базе Amazon Linux 2023:
- Содержит скрипты инициализации, выполняемые при запуске EC2 инстансов
- Настраивает системные параметры, пакеты и конфигурации для оптимальной работы как узла Kubernetes
- Устанавливает необходимые компоненты для интеграции с EKS
- Производит регистрацию узла в кластере EKS

Использование шаблона позволяет стандартизировать конфигурацию новых узлов и автоматизировать их присоединение к кластеру.

#### sqs.tf
Настраивает ресурсы SQS для работы с Karpenter:
- Создает очереди для асинхронной обработки сообщений для Karpenter
- Настраивает параметры очередей (политики DLQ)
- Определяет политики доступа к SQS 

#### kms.tf
Определяет настройки KMS для шифрования данных:
- Создает ключи KMS для шифрования секретов Kubernetes, включая:
  - Секреты для хранения учетных данных сервисных аккаунтов
  - TLS сертификаты и приватные ключи

#### openid-connect.tf
Настраивает интеграцию OpenID Connect (OIDC) с EKS:
- Создает OIDC провайдера на стороне AWS IAM
- Связывает провайдера с кластером EKS
- Параметры аутентификации и проверки подлинности

Этот файл является требуется подам в Kubernetes безопасно использовать IAM роли.

#### oidc-iam-policies.tf
Определяет IAM политики, необходимые для работы OIDC и сервисных аккаунтов:
- Создает IAM роли, которые могут быть приняты сервисными аккаунтами Kubernetes
- Определяет политики доступа для этих ролей
- Настраивает отношения доверия между IAM и сервисными аккаунтами Kubernetes

Этот файл реализует подробные политики доступа, следуя принципу наименьших привилегий для компонентов системы.

### eks/modules/configs/
#### core-dns.json
Конфигурационный файл в формате JSON для настройки CoreDNS:
- Определяет параметры кэширования DNS-запросов
- Настраивает правила перенаправления для различных доменов
- Устанавливает параметры таймаутов и повторных попыток
- Конфигурирует логирование DNS-запросов

### eks/modules/policies/
#### oidc_assume_role_policy.json
Конфигурационный файл для настройки IAM политики доверия (trust policy) при работе с OIDC:
- Определяет политику доверительных отношений между IAM ролями AWS и сервисными аккаунтами Kubernetes
- Обеспечивает реализацию IAM Roles for Service Accounts (IRSA) в EKS
- Позволяет подам в Kubernetes временно получать доступ к AWS ресурсам через механизм AssumeRoleWithWebIdentity
- Заменяет необходимость хранения долгосрочных AWS учетных данных в секретах Kubernetes

OIDC механизм использую в место статических учетных данных и IAM ролей nodes

## Архитектура

Основные компоненты архитектуры:
1. **Сетевая инфраструктура**
   - Изолированный VPC с публичными и приватными подсетями
   - subnets в нескольких зонах доступности
   - Приватный доступ к AWS сервисам через VPC Endpoints
   
2. **Control Plane EKS**
   - Управляется AWS с автоматическими обновлениями 
   - Мультизональное развертывание

3. **Data Plane EKS**
   - Динамическое управление с использованием Karpenter
   - Оптимизированные группы узлов для различных нагрузок

4. **Безопасность**
   - VPC, группы безопасности, IAM, RBAC
   - Изоляция рабочих нагрузокние в состоянии покоя и при передаче данных

5. **Мониторинг**
   - Интеграция с CloudWatch для метрик и логов
   - Alarms по ключевым показателям утилизации ресурсов

### Приминение

   ```bash
   terraform init
   terraform plan -out=plan.out
   terraform apply plan.out
   ```

   ```bash
   aws eks update-kubeconfig --name infra-demo --region eu-central-1
   ```

## Helm Charts с NGINX

### Структура чарта

```
nginx-chart/
├── Chart.yaml           
├── values.yaml          
├── templates/          
│   ├── deployment.yaml  # Основной деплоймент NGINX
│   ├── service.yaml     # Сервис для доступа к NGINX
│   ├── configmap.yaml   # Конфигурация NGINX
│   ├── hpa.yaml         # Horizontal Pod Autoscaler 
│   ├── keda-scaledobject.yaml  # KEDA ScaledObject
│   ├── serviceaccount.yaml     # ServiceAccount с правами доступа к метрикам
│   ├── prometheusrule.yaml     # Правила Prometheus для алертов
│   └── servicemonitor.yaml     # ServiceMonitor для сбора метрик
├── templates/helpers/   # 
│   └── _helpers.tpl     # Функции чарта
└── templates/tests/     # Тесты
    └── test-connection.yaml
```

### Конигурацтя NGINX с KEDA

скалирование NGINX KEDAой на основе ошибок 504:

#### values.yaml

```yaml
# Основные настройки NGINX
nginx:
  image:
    repository: nginx
    tag: 1.25.3-alpine
    pullPolicy: IfNotPresent
  
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 300m
      memory: 256Mi
  
  # Конфиг NGINX
  config:
    workerProcesses: auto
    workerConnections: 1024
    keepaliveTimeout: 65
    clientMaxBodySize: 10m
    logFormat: |
      '$remote_addr - $remote_user [$time_local] "$request" '
      '$status $body_bytes_sent "$http_referer" '
      '"$http_user_agent" "$http_x_forwarded_for" '
      '$request_time $upstream_response_time'
    errorLogLevel: warn

# реплики
replicaCount:
  min: 3    
  max: 10  

# KEDA - управление hpa контроллером
keda:
  enabled: true
  pollingInterval: 15   # Интервал на запрос метрик 
  cooldownPeriod: 300   # Период ожидания после скалирования
  
  # триггеры скалирования
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc.cluster.local:9090
        metricName: nginx_requests_status_504_percentile
        query: |
          quantile_over_time(0.95, 
            sum(rate(nginx_http_requests_total{status="504"}[5m])) / 
            sum(rate(nginx_http_requests_total[5m])) * 100
          )[30m:1m]
        threshold: "5"   # Процент 504 ошибок запуска скалирования
```

#### templates/saledobject.yaml

```yaml
{{- if .Values.keda.enabled }}
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "nginx.fullname" . }}
  minReplicaCount: {{ .Values.replicaCount.min }}
  maxReplicaCount: {{ .Values.replicaCount.max }}
  pollingInterval: {{ .Values.keda.pollingInterval }}
  cooldownPeriod: {{ .Values.keda.cooldownPeriod }}
  triggers:
  {{- range .Values.keda.triggers }}
  - type: {{ .type }}
    metadata:
      {{- range $key, $value := .metadata }}
      {{ $key }}: {{ $value | quote }}
      {{- end }}
  {{- end }}
{{- end }}
```

#### templates/configmap.yaml

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "nginx.fullname" . }}-config
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
data:
  nginx.conf: |-
    user nginx;
    worker_processes {{ .Values.nginx.config.workerProcesses }};
    error_log /var/log/nginx/error.log {{ .Values.nginx.config.errorLogLevel }};
    pid /var/run/nginx.pid;

    events {
      worker_connections {{ .Values.nginx.config.workerConnections }};
    }

    http {
      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      log_format main {{ .Values.nginx.config.logFormat }};
      access_log /var/log/nginx/access.log main;

      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      keepalive_timeout {{ .Values.nginx.config.keepaliveTimeout }};
      
      # настройки таймаутов для предотвращения ошибок 504
      proxy_connect_timeout 75s;
      proxy_read_timeout 300s;
      proxy_send_timeout 300s;
      
      # метрик для Prometheus
      server {
        listen 8080;
        location /metrics {
          stub_status on;
        }
      }

      server {
        listen 80;
        
        location / {
          root /usr/share/nginx/html;
          index index.html index.htm;
        }
        
        client_max_body_size {{ .Values.nginx.config.clientMaxBodySize }};

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
          root /usr/share/nginx/html;
        }
      }
    }
```

### Тактика скалирования KEDA

1. **Определение метрик**:
   - 95-й персентиль для 504 ошибок
   - соотношение 504 ошибок к общему количеству запросов

2. **Настройка порогов**:
   - берем исторические данные
   - определяем порог 5%

3. **Предотвращение частых не требуемых скалирований *:
   - используем cooldownPeriod (300-600 секунд)
   - определяем hysterlSize, чтобы избежать частых изменений реплик

4. **Мониторинг**:
   - ServiceMonitor для сбора метрик NGINX /metrics

5. **Ресурсные лимиты**:
   - устанавливайте адекватные запросы на ресурсы для подов NGINX
   - Ззаранее оцениваем капасити кластера для выделения ресурсов подам

6. **Реокмендации к тестированию для прод среды**:
   - стресс-тест для проверки автоскалирования
   - нагрузочное тестирование для определения оптимальных порогов

### для метрик

```yaml
# templates/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
spec:
  selector:
    matchLabels:
      {{- include "nginx.selectorLabels" . | nindent 6 }}
  endpoints:
  - port: metrics
    interval: 15s
    path: /metrics
```

### PrometheusRule для алертов по 504 (можем часть helm мониторинга сделать, практика обсуждается)

```yaml
# templates/prometheusrule.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: {{ include "nginx.fullname" . }}-alerts
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
spec:
  groups:
  - name: nginx.rules
    rules:
    - alert: NginxHigh504Rate
      expr: |
        sum(rate(nginx_http_requests_total{status="504"}[5m])) / 
        sum(rate(nginx_http_requests_total[5m])) * 100 > 5
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Высокий процент 504 ошибок в NGINX"
        description: "Процент 504 ошибок превышает 5% в течение 5 минут."
```

### Пример деплоя

```bash
# установка KEDA
helm repo add kedacore https://kedacore.github.io/charts
helm repo update
helm install keda kedacore/keda --namespace keda --create-namespace

# установка Helm чарта NGINX
helm -n demo install nginx-demo-tast ./nginx-chart -f values.yaml
```

### Настройка RBAC для NGINX с KEDA

#### templates/serviceaccount.yaml

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
```

#### templates/role.yaml

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
rules:
  # права для работы NGINX
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
  # права для доступа к endpoints Kubernetes, если используется NGINX Ingress
  {{- if .Values.ingress.enabled }}
  - apiGroups: [""]
    resources: ["services", "endpoints"]
    verbs: ["get", "list", "watch"]
  {{- end }}
  # права для KEDA на масштабирование деплоймента
  {{- if .Values.keda.enabled }}
  - apiGroups: ["apps"]
    resources: ["deployments"]
    resourceNames: ["{{ include "nginx.fullname" . }}"]
    verbs: ["get", "update", "patch"]
  - apiGroups: ["apps"]
    resources: ["deployments/scale"]
    resourceNames: ["{{ include "nginx.fullname" . }}"]
    verbs: ["get", "update", "patch"]
  {{- end }}
```

#### templates/rolebinding.yaml

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
subjects:
  - kind: ServiceAccount
    name: {{ include "nginx.fullname" . }}
    namespace: {{ .Release.Namespace }}
roleRef:
  kind: Role
  name: {{ include "nginx.fullname" . }}
  apiGroup: rbac.authorization.k8s.io
```

#### Дополнительные разрешения для Prometheus operator

```yaml
# templates/clusterrole.yaml (если требуется доступ на уровне кластера)
{{- if .Values.prometheus.enabled }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "nginx.fullname" . }}-metrics
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: ["nodes", "nodes/proxy", "services", "endpoints", "pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "nginx.fullname" . }}-metrics
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "nginx.fullname" . }}-metrics
subjects:
  - kind: ServiceAccount
    name: {{ include "nginx.fullname" . }}
    namespace: {{ .Release.Namespace }}
{{- end }}
```

### практики RBAC для NGINX в кубе

1. **Принцип наименьших привилегий**:
   - права указываем только необходимые
   - Role вместо ClusterRole, ограничиваем в одном namespace

2. **Специализированный ServiceAccount**:
   - ServiceAccount для каждого приложения (не использвем sa default)

3. **Ограничение resourceNames**:
   - ограничиваем доступы до конкретных ресурсов по имени (важно для не безопасных методов patch)

4. **Разделение ответственности**:
   - каждый компонент с своими ограниченями: NGINX, KEDA, сборщики метрик
   - права на каждую роль

5. **Аудит разрешений**:
   - Регулярно проверяйте используемые разрешения с помощью `kubectl auth can-i`
   - Используйте инструменты статического анализа RBAC манифестов

6. **deployment.yaml c использованием ServiceAccount**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "nginx.fullname" . }}
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount.min }}
  selector:
    matchLabels:
      {{- include "nginx.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "nginx.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ include "nginx.fullname" . }}
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.nginx.image.repository }}:{{ .Values.nginx.image.tag }}"
          imagePullPolicy: {{ .Values.nginx.image.pullPolicy }}
```

### RBAC

```yaml
rbac:
  # создание RBAC
  create: true
  # Создавать ClusterRole и ClusterRoleBinding
  clusterWide: false
  additionalRules: []
  # - apiGroups: [""]
  #   resources: ["pods/log"]
  #   verbs: ["get", "list"]

# ServiceAccount
serviceAccount:
  create: true
  name: ""
  # Аннотации arn ServiceAccount
  annotations: {}
  # eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
```  

### Ограничение сетевого доступа с NetworkPolicy

Для сетевой изоляции NGINX pods и доступа только в пределах namespace demo:

#### templates/networkpolicy.yaml

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "nginx.fullname" . }}-network-policy
  labels:
    {{- include "nginx.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "nginx.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
    - Egress
  # разрешаем входящий трафик только из того же namespace
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ .Release.Namespace }}
  # разрешаем исходящий трафик только в пределах namespace и для dns
  egress:
    # трафик в пределах namespace demo
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ .Release.Namespace }}
    # dns трафик (fqdn нужно резолвить в кластере)
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # доступ к API Kubernetes для KEDA
    {{- if .Values.keda.enabled }}
    - to:
        - ipBlock:
            cidr: {{ .Values.kubernetes.apiServer }}/32
      ports:
        - protocol: TCP
          port: 443
    {{- end }}
```

### NetworkPolicy

```yaml
networkPolicy:
  enabled: true
```

### практики для NetworkPolicy

1. **Явный запрет по умолчанию**:
   - Запрещаем весь трафик
   - policyTypes с указанием как Ingress, так и Egress

2. **Минимальный набор правил**:
   - только тот трафик, который действительно необходим для работы приложения

3. **Четкое определение селекторов**:
   - используем точные selectors для подов и namespace
   - не используем такие широкие правила `podSelector: {}`

4. **Изоляция между namespace**:
   - Демонстрирую если приложение публичное и нет необходимости ограничивать доступ к сетемым ресурсам

5. **Тестирование политик**:
     ```bash
     kubectl -n demo exec -it <pod-name> -- curl -v 
     kubectl -n default exec -it <pod-name> -- curl -v 
     ```

6. **Мониторинг заблокированных соединений**:
   - логирование дропнутых пакетов
   - добавляем в мониторинг для отслеживания блокировок пакетов

### Пример использования с NGINX и KEDA
KEDA требует доступа к метрикам (Prometheus) и API k8s (указал выше к dns и api server)

```yaml
networkPolicy:
  additionalRules:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app: prometheus
      ports:
        - protocol: TCP
          port: 9090
```  
