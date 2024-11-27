from typing import Dict

SUPPORTED_PROVIDERS = {"aws", "azure", "gcp", "kubernetes"}


def get_prowler_services(provider: str) -> Dict[str, str]:
    """Get the services available for the specified provider.

    Args:
        provider: The provider to get the services for.
    Returns:
        A dictionary with the services available for the specified provider and their descriptions.
    """

    if provider == "aws":
        return {
            "accessanalyzer": "Analyzes IAM policies to identify potential security risks.",
            "account": "Manages AWS account settings and operations.",
            "acm": "AWS Certificate Manager - handles SSL/TLS certificates for secure connections.",
            "apigateway": "Creates and manages APIs to enable access to backend services.",
            "apigatewayv2": "Supports HTTP, WebSocket APIs, and improved integration options.",
            "appstream": "Provides a secure, managed application streaming service.",
            "appsync": "Enables GraphQL APIs for application data access in real-time.",
            "athena": "Interactive query service using standard SQL on S3 data.",
            "autoscaling": "Automatically adjusts resource capacity to maintain performance.",
            "awslambda": "Run code in response to events without provisioning servers.",
            "backup": "Centralized backup service for AWS services and on-premises data.",
            "bedrock": "Provides access to foundational models for AI/ML applications.",
            "cloudformation": "Infrastructure as code service to model and provision resources.",
            "cloudfront": "Content delivery network (CDN) for low-latency content delivery.",
            "cloudtrail": "Tracks user activity and API usage for governance and auditing.",
            "cloudwatch": "Monitors applications, resources, and logs for operational insights.",
            "codeartifact": "Manages software package repositories for application development.",
            "codebuild": "Fully managed build service for continuous integration and deployment.",
            "cognito": "User authentication and authorization service for web and mobile apps.",
            "config": "Tracks AWS resource configuration changes for compliance auditing.",
            "datasync": "Transfers data between on-premises and AWS storage services.",
            "directconnect": "Dedicated network connections between on-premises and AWS.",
            "directoryservice": "Manages Active Directory services in the AWS cloud.",
            "dlm": "Data Lifecycle Manager for managing EBS snapshots and automation.",
            "dms": "Database migration service for moving databases to AWS.",
            "documentdb": "Managed NoSQL database service for document storage (MongoDB compatible).",
            "drs": "Disaster recovery service to replicate workloads across AWS regions.",
            "dynamodb": "Fully managed NoSQL database for key-value and document data.",
            "ec2": "Elastic Compute Cloud for scalable virtual servers.",
            "ecr": "Elastic Container Registry for storing and managing container images.",
            "ecs": "Elastic Container Service for running and managing containers.",
            "efs": "Elastic File System - scalable, managed NFS storage.",
            "eks": "Elastic Kubernetes Service for running Kubernetes clusters.",
            "elasticache": "In-memory caching services (Memcached and Redis).",
            "elasticbeanstalk": "Platform as a service for deploying and managing web apps.",
            "elb": "Elastic Load Balancer - distributes incoming application traffic.",
            "elbv2": "Advanced load balancer with support for application and network protocols.",
            "emr": "Elastic MapReduce - managed big data processing service.",
            "eventbridge": "Event-driven service for routing events between applications and AWS services.",
            "firehose": "Service for loading streaming data into AWS data stores.",
            "fms": "Firewall Manager - centralizes management of AWS WAF and Shield policies.",
            "fsx": "File storage solutions optimized for various workloads.",
            "glacier": "Long-term, low-cost storage for archiving and backups.",
            "glue": "Managed ETL service for data integration and preparation.",
            "guardduty": "Threat detection service for protecting AWS accounts and workloads.",
            "iam": "Identity and Access Management for permissions and access control.",
            "inspector2": "Automated security assessment for identifying vulnerabilities.",
            "kafka": "Managed Apache Kafka service for real-time streaming data applications.",
            "kinesis": "Service for processing and analyzing streaming data in real-time.",
            "kms": "Key Management Service for encryption key creation and control.",
            "lightsail": "Simple cloud hosting with pre-configured virtual private servers.",
            "macie": "Data security and privacy service with machine learning for sensitive data.",
            "memorydb": "Redis-compatible database optimized for real-time applications.",
            "mq": "Managed message broker service for open-source message queues.",
            "neptune": "Graph database service for highly connected datasets.",
            "networkfirewall": "Managed network firewall service for traffic inspection and control.",
            "opensearch": "Search and analytics engine for operational and application data.",
            "organizations": "Manages multiple AWS accounts under a single organization.",
            "rds": "Relational Database Service for managed SQL databases.",
            "redshift": "Data warehouse service for analytics at scale.",
            "resourceexplorer2": "Search across AWS resources using a unified query service.",
            "route53": "Scalable DNS and domain name management service.",
            "s3": "Simple Storage Service for object storage and retrieval.",
            "sagemaker": "Managed service for building, training, and deploying ML models.",
            "secretsmanager": "Securely manages and rotates application secrets.",
            "securityhub": "Centralized view and compliance checks for AWS security services.",
            "servicecatalog": "Manages approved cloud products for organization-wide use.",
            "ses": "Simple Email Service for sending and receiving emails.",
            "shield": "DDoS protection for applications running on AWS.",
            "sns": "Simple Notification Service for messaging and alerts.",
            "sqs": "Simple Queue Service for message queuing between application components.",
            "ssm": "Systems Manager for operational management of AWS resources.",
            "ssmincidents": "Incident management service for responding to operational issues.",
            "storagegateway": "Hybrid cloud storage for on-premises integration.",
            "transfer": "Managed service for transferring files via SFTP, FTPS, or FTP.",
            "trustedadvisor": "Resource optimization and best practices recommendations.",
            "vpc": "Virtual Private Cloud for secure, isolated network environments.",
            "waf": "Web Application Firewall for application-level security.",
            "wafv2": "Enhanced web application firewall with additional rule options.",
            "wellarchitected": "Framework for assessing and improving cloud architectures.",
            "workspaces": "Managed virtual desktop service for remote work.",
        }

    elif provider == "azure":
        return {
            "aisearch": "Azure Cognitive Search - AI-powered search service for app integration.",
            "aks": "Azure Kubernetes Service - Managed Kubernetes for containerized applications.",
            "app": "Azure App Service - Platform for building and hosting web apps and APIs.",
            "appinsights": "Application Insights - Monitoring and analytics for application performance.",
            "containerregistry": "Azure Container Registry - Stores and manages container images.",
            "cosmosdb": "Globally distributed, multi-model NoSQL database for modern applications.",
            "defender": "Microsoft Defender for Cloud - Threat protection for Azure and hybrid environments.",
            "entra": "Azure Entra - Unified identity and access management solutions.",
            "iam": "Identity and Access Management - Manages user roles and access permissions.",
            "keyvault": "Centralized management for secrets, keys, and certificates.",
            "monitor": "Azure Monitor - Collects and analyzes metrics, logs, and diagnostics.",
            "mysql": "Azure Database for MySQL - Managed MySQL relational database service.",
            "network": "Azure Networking - Virtual networks, load balancers, and connectivity services.",
            "policy": "Azure Policy - Enforces compliance and governance across Azure resources.",
            "postgresql": "Azure Database for PostgreSQL - Managed PostgreSQL database service.",
            "sqlserver": "Azure SQL - Fully managed SQL Server database services.",
            "storage": "Azure Storage - Scalable, durable cloud storage for data and files.",
            "vm": "Azure Virtual Machines - Scalable virtualized compute resources.",
        }
    elif provider == "gcp":
        return {
            "apikeys": "API Keys - Manages API keys for authenticating and authorizing API requests.",
            "artifacts": "Artifact Registry - Stores and manages build artifacts and container images.",
            "bigquery": "Fully managed data warehouse for fast SQL queries on large datasets.",
            "cloudsql": "Managed relational database service for MySQL, PostgreSQL, and SQL Server.",
            "cloudstorage": "Object storage for scalable and durable data storage.",
            "compute": "Google Compute Engine - Virtual machines for scalable compute workloads.",
            "dataproc": "Managed Spark and Hadoop service for big data processing.",
            "dns": "Cloud DNS - Scalable, reliable, and managed Domain Name System (DNS) service.",
            "gcr": "Google Container Registry - Stores, manages, and secures Docker container images.",
            "gke": "Google Kubernetes Engine - Managed Kubernetes service for containerized applications.",
            "iam": "Identity and Access Management - Manages permissions and access to resources.",
            "kms": "Key Management Service - Manages encryption keys for securing data.",
            "logging": "Cloud Logging - Collects, stores, and analyzes log data from applications and services.",
        }

    elif provider == "kubernetes":
        return {
            "apiserver": "API Server - Frontend for the Kubernetes control plane, handling API requests.",
            "controllermanager": "Controller Manager - Runs controllers to maintain the desired state of the cluster.",
            "core": "Core Components - Essential Kubernetes objects like Pods, Services, and ConfigMaps.",
            "etcd": "etcd - Distributed key-value store for storing all cluster state and configuration data.",
            "kubelet": "Kubelet - Node agent that ensures containers are running as specified in Pod specs.",
            "rbac": "Role-Based Access Control - Manages permissions and access control for Kubernetes resources.",
            "scheduler": "Scheduler - Assigns workloads (Pods) to nodes based on resource availability.",
        }

    else:
        raise ValueError(f"Provider '{provider}' is not supported")
