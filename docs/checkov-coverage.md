# Checkov coverage by release

> Generated file. `tools/generate_checkov_coverage.py` renders it from the installed Checkov catalogue, the mapping registries and `tools/checkov_triage.yaml`. Do not edit it by hand; CI (via `--check`) fails if it drifts, so a Checkov bump regenerates it.

Checkov 3.4.5. Every check of this release with a `CKV_` / `CKV2_` AWS, Azure, GCP, Kubernetes or `CKV_TF_` ID is listed once:

- **mapped**: has a registry entry with article references.
- **intentionally unmapped**: reviewed and left out on purpose; the reason is given.
- **untriaged**: not reviewed yet. This is the default and is not a defect; the mapping is deliberately a subset (see [Checks still intentionally unmapped](check-mapping-table.md#checks-still-intentionally-unmapped)).

## Summary

| Provider | Total | Mapped | Intentionally unmapped | Untriaged |
|----------|------:|-------:|-----------------------:|----------:|
| AWS | 456 | 180 | 6 | 270 |
| Azure | 302 | 23 | 0 | 279 |
| GCP | 162 | 22 | 0 | 140 |
| Kubernetes | 119 | 24 | 0 | 95 |
| Terraform (cloud-agnostic) | 2 | 2 | 0 | 0 |
| **All** | 1041 | 251 | 6 | 784 |

## AWS

| Check | Name | Status | Reason |
|-------|------|--------|--------|
| CKV2_AWS_1 | Ensure that all NACL are attached to subnets | untriaged |  |
| CKV2_AWS_2 | Ensure that only encrypted EBS volumes are attached to EC2 instances | mapped |  |
| CKV2_AWS_3 | Ensure GuardDuty is enabled to specific org/region | untriaged |  |
| CKV2_AWS_4 | Ensure API Gateway stage have logging level defined as appropriate | untriaged |  |
| CKV2_AWS_5 | Ensure that Security Groups are attached to another resource | mapped |  |
| CKV2_AWS_6 | Ensure that S3 bucket has a Public Access block | mapped |  |
| CKV2_AWS_7 | Ensure that Amazon EMR clusters' security groups are not open to the world | untriaged |  |
| CKV2_AWS_8 | Ensure that RDS clusters has backup plan of AWS Backup | mapped |  |
| CKV2_AWS_9 | Ensure that EBS are added in the backup plans of AWS Backup | untriaged |  |
| CKV2_AWS_10 | Ensure CloudTrail trails are integrated with CloudWatch Logs | mapped |  |
| CKV2_AWS_11 | Ensure VPC flow logging is enabled in all VPCs | mapped |  |
| CKV2_AWS_12 | Ensure the default security group of every VPC restricts all traffic | mapped |  |
| CKV2_AWS_14 | Ensure that IAM groups includes at least one IAM user | untriaged |  |
| CKV2_AWS_15 | Ensure that auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks. | untriaged |  |
| CKV2_AWS_16 | Ensure that Auto Scaling is enabled on your DynamoDB tables | untriaged |  |
| CKV2_AWS_18 | Ensure that Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup | untriaged |  |
| CKV2_AWS_19 | Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances | untriaged |  |
| CKV2_AWS_20 | Ensure that ALB redirects HTTP requests into HTTPS ones | mapped |  |
| CKV2_AWS_21 | Ensure that all IAM users are members of at least one IAM group. | untriaged |  |
| CKV2_AWS_22 | Ensure an IAM User does not have access to the console | untriaged |  |
| CKV2_AWS_23 | Route53 A Record has Attached Resource | untriaged |  |
| CKV2_AWS_27 | Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled | mapped |  |
| CKV2_AWS_28 | Ensure public facing ALB are protected by WAF | mapped |  |
| CKV2_AWS_29 | Ensure public API gateway are protected by WAF | mapped |  |
| CKV2_AWS_30 | Ensure Postgres RDS as aws_db_instance has Query Logging enabled | mapped |  |
| CKV2_AWS_31 | Ensure WAF2 has a Logging Configuration | mapped |  |
| CKV2_AWS_32 | Ensure CloudFront distribution has a response headers policy attached | mapped |  |
| CKV2_AWS_33 | Ensure AppSync is protected by WAF | untriaged |  |
| CKV2_AWS_34 | AWS SSM Parameter should be Encrypted | mapped |  |
| CKV2_AWS_35 | AWS NAT Gateways should be utilized for the default route | untriaged |  |
| CKV2_AWS_36 | Ensure terraform is not sending SSM secrets to untrusted domains over HTTP | untriaged |  |
| CKV2_AWS_37 | Ensure CodeCommit associates an approval rule | untriaged |  |
| CKV2_AWS_38 | Ensure Domain Name System Security Extensions (DNSSEC) signing is enabled for Amazon Route 53 public hosted zones | untriaged |  |
| CKV2_AWS_39 | Ensure Domain Name System (DNS) query logging is enabled for Amazon Route 53 hosted zones | untriaged |  |
| CKV2_AWS_40 | Ensure AWS IAM policy does not allow full IAM privileges | mapped |  |
| CKV2_AWS_41 | Ensure an IAM role is attached to EC2 instance | mapped |  |
| CKV2_AWS_42 | Ensure AWS CloudFront distribution uses custom SSL certificate | mapped |  |
| CKV2_AWS_43 | Ensure S3 Bucket does not allow access to all Authenticated users | untriaged |  |
| CKV2_AWS_44 | Ensure AWS route table with VPC peering does not contain routes overly permissive to all traffic | untriaged |  |
| CKV2_AWS_45 | Ensure AWS Config recorder is enabled to record all supported resources | untriaged |  |
| CKV2_AWS_46 | Ensure AWS CloudFront Distribution with S3 have Origin Access set to enabled | untriaged |  |
| CKV2_AWS_47 | Ensure AWS CloudFront attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability | mapped |  |
| CKV2_AWS_48 | Ensure AWS Config must record all possible resources | untriaged |  |
| CKV2_AWS_49 | Ensure AWS Database Migration Service endpoints have SSL configured | untriaged |  |
| CKV2_AWS_50 | Ensure AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to enabled | mapped |  |
| CKV2_AWS_51 | Ensure AWS API Gateway endpoints uses client certificate authentication | mapped |  |
| CKV2_AWS_52 | Ensure AWS ElasticSearch/OpenSearch Fine-grained access control is enabled | mapped |  |
| CKV2_AWS_53 | Ensure AWS API gateway request is validated | untriaged |  |
| CKV2_AWS_54 | Ensure AWS CloudFront distribution is using secure SSL protocols for HTTPS communication | untriaged |  |
| CKV2_AWS_55 | Ensure AWS EMR cluster is configured with security configuration | untriaged |  |
| CKV2_AWS_56 | Ensure AWS Managed IAMFullAccess IAM policy is not used. | untriaged |  |
| CKV2_AWS_57 | Ensure Secrets Manager secrets should have automatic rotation enabled | mapped |  |
| CKV2_AWS_58 | Ensure AWS Neptune cluster deletion protection is enabled | mapped |  |
| CKV2_AWS_59 | Ensure ElasticSearch/OpenSearch has dedicated master node enabled | mapped |  |
| CKV2_AWS_60 | Ensure RDS instance with copy tags to snapshots is enabled | mapped |  |
| CKV2_AWS_61 | Ensure that an S3 bucket has a lifecycle configuration | mapped |  |
| CKV2_AWS_62 | Ensure S3 buckets should have event notifications enabled | mapped |  |
| CKV2_AWS_63 | Ensure Network firewall has logging configuration defined | untriaged |  |
| CKV2_AWS_64 | Ensure KMS key Policy is defined | mapped |  |
| CKV2_AWS_65 | Ensure access control lists for S3 buckets are disabled | untriaged |  |
| CKV2_AWS_66 | Ensure MWAA environment is not publicly accessible | untriaged |  |
| CKV2_AWS_68 | Ensure SageMaker notebook instance IAM policy is not overly permissive | untriaged |  |
| CKV2_AWS_69 | Ensure AWS RDS database instance configured with encryption in transit | mapped |  |
| CKV2_AWS_70 | Ensure API gateway method has authorization or API key set | untriaged |  |
| CKV2_AWS_71 | Ensure AWS ACM Certificate domain name does not include wildcards | untriaged |  |
| CKV2_AWS_72 | Ensure AWS CloudFront origin protocol policy enforces HTTPS-only | untriaged |  |
| CKV2_AWS_73 | Ensure AWS SQS uses CMK not AWS default keys for encryption | untriaged |  |
| CKV2_AWS_74 | Ensure AWS Load Balancers use strong ciphers | untriaged |  |
| CKV2_AWS_75 | Ensure no open CORS policy | untriaged |  |
| CKV2_AWS_76 | Ensure AWS ALB attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability | untriaged |  |
| CKV2_AWS_77 | Ensure AWS API Gateway Rest API attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability | untriaged |  |
| CKV2_AWS_78 | Ensure AWS AppSync attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability | untriaged |  |
| CKV_AWS_1 | Ensure IAM policies that allow full "*-*" administrative privileges are not created | untriaged |  |
| CKV_AWS_2 | Ensure ALB protocol is HTTPS | mapped |  |
| CKV_AWS_3 | Ensure all data stored in the EBS is securely encrypted | mapped |  |
| CKV_AWS_5 | Ensure all data stored in the Elasticsearch is securely encrypted at rest | mapped |  |
| CKV_AWS_6 | Ensure all Elasticsearch has node-to-node encryption enabled | untriaged |  |
| CKV_AWS_7 | Ensure rotation for customer created CMKs is enabled | mapped |  |
| CKV_AWS_8 | Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted | mapped |  |
| CKV_AWS_9 | Ensure IAM password policy expires passwords within 90 days or less | mapped |  |
| CKV_AWS_10 | Ensure IAM password policy requires minimum length of 14 or greater | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_11 | Ensure IAM password policy requires at least one lowercase letter | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_12 | Ensure IAM password policy requires at least one number | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_13 | Ensure IAM password policy prevents password reuse | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_14 | Ensure IAM password policy requires at least one symbol | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_15 | Ensure IAM password policy requires at least one uppercase letter | intentionally unmapped | Represented by the mapped CKV_AWS_9 account-level password-policy check. |
| CKV_AWS_16 | Ensure all data stored in the RDS is securely encrypted at rest | mapped |  |
| CKV_AWS_17 | Ensure all data stored in RDS is not publicly accessible | mapped |  |
| CKV_AWS_18 | Ensure the S3 bucket has access logging enabled | mapped |  |
| CKV_AWS_19 | Ensure all data stored in the S3 bucket is securely encrypted at rest | untriaged |  |
| CKV_AWS_20 | S3 Bucket has an ACL defined which allows public READ access. | mapped |  |
| CKV_AWS_21 | Ensure all data stored in the S3 bucket have versioning enabled | mapped |  |
| CKV_AWS_22 | Ensure SageMaker Notebook is encrypted at rest using KMS CMK | untriaged |  |
| CKV_AWS_23 | Ensure every security group and rule has a description | mapped |  |
| CKV_AWS_24 | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 | mapped |  |
| CKV_AWS_25 | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 | mapped |  |
| CKV_AWS_26 | Ensure all data stored in the SNS topic is encrypted | mapped |  |
| CKV_AWS_27 | Ensure all data stored in the SQS queue is encrypted | untriaged |  |
| CKV_AWS_28 | Ensure DynamoDB point in time recovery (backup) is enabled | mapped |  |
| CKV_AWS_29 | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at rest | mapped |  |
| CKV_AWS_30 | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit | mapped |  |
| CKV_AWS_31 | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit and has auth token | mapped |  |
| CKV_AWS_32 | Ensure ECR policy is not set to public | untriaged |  |
| CKV_AWS_33 | Ensure KMS key policy does not contain wildcard (*) principal | untriaged |  |
| CKV_AWS_34 | Ensure CloudFront distribution ViewerProtocolPolicy is set to HTTPS | mapped |  |
| CKV_AWS_35 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | mapped |  |
| CKV_AWS_36 | Ensure CloudTrail log file validation is enabled | mapped |  |
| CKV_AWS_37 | Ensure Amazon EKS control plane logging is enabled for all log types | mapped |  |
| CKV_AWS_38 | Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0 | mapped |  |
| CKV_AWS_39 | Ensure Amazon EKS public endpoint disabled | mapped |  |
| CKV_AWS_40 | Ensure IAM policies are attached only to groups or roles (Reducing access management complexity may in-turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.) | mapped |  |
| CKV_AWS_41 | Ensure no hard coded AWS access key and secret key exists in provider | mapped |  |
| CKV_AWS_42 | Ensure EFS is securely encrypted | untriaged |  |
| CKV_AWS_43 | Ensure Kinesis Stream is securely encrypted | untriaged |  |
| CKV_AWS_44 | Ensure Neptune storage is securely encrypted | mapped |  |
| CKV_AWS_45 | Ensure no hard-coded secrets exist in lambda environment | mapped |  |
| CKV_AWS_46 | Ensure no hard-coded secrets exist in EC2 user data | mapped |  |
| CKV_AWS_47 | Ensure DAX is encrypted at rest (default is unencrypted) | untriaged |  |
| CKV_AWS_48 | Ensure MQ Broker logging is enabled | untriaged |  |
| CKV_AWS_49 | Ensure no IAM policies documents allow "*" as a statement's actions | untriaged |  |
| CKV_AWS_50 | X-Ray tracing is enabled for Lambda | mapped |  |
| CKV_AWS_51 | Ensure ECR Image Tags are immutable | mapped |  |
| CKV_AWS_53 | Ensure S3 bucket has block public ACLS enabled | mapped |  |
| CKV_AWS_54 | Ensure S3 bucket has block public policy enabled | mapped |  |
| CKV_AWS_55 | Ensure S3 bucket has ignore public ACLs enabled | mapped |  |
| CKV_AWS_56 | Ensure S3 bucket has 'restrict_public_buckets' enabled | mapped |  |
| CKV_AWS_57 | S3 Bucket has an ACL defined which allows public WRITE access. | untriaged |  |
| CKV_AWS_58 | Ensure EKS Cluster has Secrets Encryption Enabled | mapped |  |
| CKV_AWS_59 | Ensure there is no open access to back-end resources through API | untriaged |  |
| CKV_AWS_60 | Ensure IAM role allows only specific services or principals to assume it | untriaged |  |
| CKV_AWS_61 | Ensure AWS IAM policy does not allow assume role permission across all services | untriaged |  |
| CKV_AWS_62 | Ensure IAM policies that allow full "*-*" administrative privileges are not created | mapped |  |
| CKV_AWS_63 | Ensure no IAM policies documents allow "*" as a statement's actions | mapped |  |
| CKV_AWS_64 | Ensure all data stored in the Redshift cluster is securely encrypted at rest | mapped |  |
| CKV_AWS_65 | Ensure container insights are enabled on ECS cluster | mapped |  |
| CKV_AWS_66 | Ensure that CloudWatch Log Group specifies retention days | untriaged |  |
| CKV_AWS_67 | Ensure CloudTrail is enabled in all Regions | mapped |  |
| CKV_AWS_68 | CloudFront Distribution should have WAF enabled | mapped |  |
| CKV_AWS_69 | Ensure MQ Broker is not publicly exposed | untriaged |  |
| CKV_AWS_70 | Ensure S3 bucket does not allow an action with any Principal | mapped |  |
| CKV_AWS_71 | Ensure Redshift Cluster logging is enabled | mapped |  |
| CKV_AWS_72 | Ensure SQS policy does not allow ALL (*) actions. | untriaged |  |
| CKV_AWS_73 | Ensure API Gateway has X-Ray Tracing enabled | mapped |  |
| CKV_AWS_74 | Ensure DocumentDB is encrypted at rest (default is unencrypted) | untriaged |  |
| CKV_AWS_75 | Ensure Global Accelerator accelerator has flow logs enabled | untriaged |  |
| CKV_AWS_76 | Ensure API Gateway has Access Logging enabled | mapped |  |
| CKV_AWS_77 | Ensure Athena Database is encrypted at rest (default is unencrypted) | untriaged |  |
| CKV_AWS_78 | Ensure that CodeBuild Project encryption is not disabled | untriaged |  |
| CKV_AWS_79 | Ensure Instance Metadata Service Version 1 is not enabled | mapped |  |
| CKV_AWS_80 | Ensure MSK Cluster logging is enabled | untriaged |  |
| CKV_AWS_81 | Ensure MSK Cluster encryption in rest and transit is enabled | untriaged |  |
| CKV_AWS_82 | Ensure Athena Workgroup should enforce configuration to prevent client disabling encryption | untriaged |  |
| CKV_AWS_83 | Ensure Elasticsearch Domain enforces HTTPS | untriaged |  |
| CKV_AWS_84 | Ensure Elasticsearch Domain Logging is enabled | mapped |  |
| CKV_AWS_85 | Ensure DocumentDB Logging is enabled | untriaged |  |
| CKV_AWS_86 | Ensure CloudFront distribution has Access Logging enabled | mapped |  |
| CKV_AWS_87 | Redshift cluster should not be publicly accessible | mapped |  |
| CKV_AWS_88 | EC2 instance should not have public IP. | untriaged |  |
| CKV_AWS_89 | DMS replication instance should not be publicly accessible | untriaged |  |
| CKV_AWS_90 | Ensure DocumentDB TLS is not disabled | untriaged |  |
| CKV_AWS_91 | Ensure the ELBv2 (Application/Network) has access logging enabled | mapped |  |
| CKV_AWS_92 | Ensure the ELB has access logging enabled | mapped |  |
| CKV_AWS_93 | Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts needing root account fixes) | untriaged |  |
| CKV_AWS_94 | Ensure Glue Data Catalog Encryption is enabled | untriaged |  |
| CKV_AWS_96 | Ensure all data stored in Aurora is securely encrypted at rest | mapped |  |
| CKV_AWS_97 | Ensure Encryption in transit is enabled for EFS volumes in ECS Task definitions | untriaged |  |
| CKV_AWS_98 | Ensure all data stored in the Sagemaker Endpoint is securely encrypted at rest | untriaged |  |
| CKV_AWS_99 | Ensure Glue Security Configuration Encryption is enabled | untriaged |  |
| CKV_AWS_100 | Ensure AWS EKS node group does not have implicit SSH access from 0.0.0.0/0 | untriaged |  |
| CKV_AWS_101 | Ensure Neptune logging is enabled | mapped |  |
| CKV_AWS_102 | Ensure Neptune Cluster instance is not publicly available | untriaged |  |
| CKV_AWS_103 | Ensure that load balancer is using at least TLS 1.2 | mapped |  |
| CKV_AWS_104 | Ensure DocumentDB has audit logs enabled | untriaged |  |
| CKV_AWS_105 | Ensure Redshift uses SSL | untriaged |  |
| CKV_AWS_106 | Ensure EBS default encryption is enabled | untriaged |  |
| CKV_AWS_107 | Ensure IAM policies does not allow credentials exposure | untriaged |  |
| CKV_AWS_108 | Ensure IAM policies does not allow data exfiltration | untriaged |  |
| CKV_AWS_109 | Ensure IAM policies does not allow permissions management / resource exposure without constraints | mapped |  |
| CKV_AWS_110 | Ensure IAM policies does not allow privilege escalation | untriaged |  |
| CKV_AWS_111 | Ensure IAM policies does not allow write access without constraints | mapped |  |
| CKV_AWS_112 | Ensure Session Manager data is encrypted in transit | untriaged |  |
| CKV_AWS_113 | Ensure Session Manager logs are enabled and encrypted | untriaged |  |
| CKV_AWS_114 | Ensure that EMR clusters with Kerberos have Kerberos Realm set | untriaged |  |
| CKV_AWS_115 | Ensure that AWS Lambda function is configured for function-level concurrent execution limit | mapped |  |
| CKV_AWS_116 | Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) | mapped |  |
| CKV_AWS_117 | Ensure that AWS Lambda function is configured inside a VPC | mapped |  |
| CKV_AWS_118 | Ensure that enhanced monitoring is enabled for Amazon RDS instances | mapped |  |
| CKV_AWS_119 | Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK | mapped |  |
| CKV_AWS_120 | Ensure API Gateway caching is enabled | mapped |  |
| CKV_AWS_121 | Ensure AWS Config is enabled in all regions | untriaged |  |
| CKV_AWS_122 | Ensure that direct internet access is disabled for an Amazon SageMaker Notebook Instance | untriaged |  |
| CKV_AWS_123 | Ensure that VPC Endpoint Service is configured for Manual Acceptance | untriaged |  |
| CKV_AWS_124 | Ensure that CloudFormation stacks are sending event notifications to an SNS topic | untriaged |  |
| CKV_AWS_126 | Ensure that detailed monitoring is enabled for EC2 instances | mapped |  |
| CKV_AWS_127 | Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Certificate Manager | mapped |  |
| CKV_AWS_129 | Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled | mapped |  |
| CKV_AWS_130 | Ensure VPC subnets do not assign public IP by default | mapped |  |
| CKV_AWS_131 | Ensure that ALB drops HTTP headers | mapped |  |
| CKV_AWS_133 | Ensure that RDS instances has backup policy | mapped |  |
| CKV_AWS_134 | Ensure that Amazon ElastiCache Redis clusters have automatic backup turned on | untriaged |  |
| CKV_AWS_135 | Ensure that EC2 is EBS optimized | mapped |  |
| CKV_AWS_136 | Ensure that ECR repositories are encrypted using KMS | mapped |  |
| CKV_AWS_137 | Ensure that Elasticsearch is configured inside a VPC | mapped |  |
| CKV_AWS_138 | Ensure that ELB is cross-zone-load-balancing enabled | untriaged |  |
| CKV_AWS_139 | Ensure that RDS clusters have deletion protection enabled | mapped |  |
| CKV_AWS_140 | Ensure that RDS global clusters are encrypted | untriaged |  |
| CKV_AWS_141 | Ensured that Redshift cluster allowing version upgrade by default | untriaged |  |
| CKV_AWS_142 | Ensure that Redshift cluster is encrypted by KMS | mapped |  |
| CKV_AWS_143 | Ensure that S3 bucket has lock configuration enabled by default | untriaged |  |
| CKV_AWS_144 | Ensure that S3 bucket has cross-region replication enabled | mapped |  |
| CKV_AWS_145 | Ensure that S3 buckets are encrypted with KMS by default | mapped |  |
| CKV_AWS_146 | Ensure that RDS database cluster snapshot is encrypted | untriaged |  |
| CKV_AWS_147 | Ensure that CodeBuild projects are encrypted using CMK | mapped |  |
| CKV_AWS_148 | Ensure no default VPC is planned to be provisioned | untriaged |  |
| CKV_AWS_149 | Ensure that Secrets Manager secret is encrypted using KMS CMK | mapped |  |
| CKV_AWS_150 | Ensure that Load Balancer has deletion protection enabled | mapped |  |
| CKV_AWS_152 | Ensure that Load Balancer (Network/Gateway) has cross-zone load balancing enabled | untriaged |  |
| CKV_AWS_153 | Autoscaling groups should supply tags to launch configurations | untriaged |  |
| CKV_AWS_154 | Ensure Redshift is not deployed outside of a VPC | mapped |  |
| CKV_AWS_155 | Ensure that Workspace user volumes are encrypted | untriaged |  |
| CKV_AWS_156 | Ensure that Workspace root volumes are encrypted | untriaged |  |
| CKV_AWS_157 | Ensure that RDS instances have Multi-AZ enabled | mapped |  |
| CKV_AWS_158 | Ensure that CloudWatch Log Group is encrypted by KMS | mapped |  |
| CKV_AWS_159 | Ensure that Athena Workgroup is encrypted | untriaged |  |
| CKV_AWS_160 | Ensure that Timestream database is encrypted with KMS CMK | untriaged |  |
| CKV_AWS_161 | Ensure RDS database has IAM authentication enabled | mapped |  |
| CKV_AWS_162 | Ensure RDS cluster has IAM authentication enabled | mapped |  |
| CKV_AWS_163 | Ensure ECR image scanning on push is enabled | mapped |  |
| CKV_AWS_164 | Ensure Transfer Server is not exposed publicly. | untriaged |  |
| CKV_AWS_165 | Ensure DynamoDB point in time recovery (backup) is enabled for global tables | untriaged |  |
| CKV_AWS_166 | Ensure Backup Vault is encrypted at rest using KMS CMK | untriaged |  |
| CKV_AWS_167 | Ensure Glacier Vault access policy is not public by only allowing specific services or principals to access it | untriaged |  |
| CKV_AWS_168 | Ensure SQS queue policy is not public by only allowing specific services or principals to access it | untriaged |  |
| CKV_AWS_169 | Ensure SNS topic policy is not public by only allowing specific services or principals to access it | untriaged |  |
| CKV_AWS_170 | Ensure QLDB ledger permissions mode is set to STANDARD | untriaged |  |
| CKV_AWS_171 | Ensure EMR Cluster security configuration encryption is using SSE-KMS | untriaged |  |
| CKV_AWS_172 | Ensure QLDB ledger has deletion protection enabled | untriaged |  |
| CKV_AWS_173 | Check encryption settings for Lambda environmental variable | mapped |  |
| CKV_AWS_174 | Verify CloudFront Distribution Viewer Certificate is using TLS v1.2 or higher | mapped |  |
| CKV_AWS_175 | Ensure WAF has associated rules | mapped |  |
| CKV_AWS_176 | Ensure Logging is enabled for WAF Web Access Control Lists | untriaged |  |
| CKV_AWS_177 | Ensure Kinesis Video Stream is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_178 | Ensure fx ontap file system is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_179 | Ensure FSX Windows filesystem is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_180 | Ensure Image Builder component is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_181 | Ensure S3 Object Copy is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_182 | Ensure DocumentDB is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_183 | Ensure EBS Snapshot Copy is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_184 | Ensure resource is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_185 | Ensure Kinesis Stream is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_186 | Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK) | mapped |  |
| CKV_AWS_187 | Ensure Sagemaker domain and notebook instance are encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_189 | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) | mapped |  |
| CKV_AWS_190 | Ensure lustre file systems is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_191 | Ensure ElastiCache replication group is encrypted by KMS using a customer managed Key (CMK) | mapped |  |
| CKV_AWS_192 | Ensure WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell | mapped |  |
| CKV_AWS_193 | Ensure AppSync has Logging enabled | untriaged |  |
| CKV_AWS_194 | Ensure AppSync has Field-Level logs enabled | untriaged |  |
| CKV_AWS_195 | Ensure Glue component has a security configuration associated | untriaged |  |
| CKV_AWS_196 | Ensure no aws_elasticache_security_group resources exist | untriaged |  |
| CKV_AWS_197 | Ensure MQ Broker Audit logging is enabled | untriaged |  |
| CKV_AWS_198 | Ensure no aws_db_security_group resources exist | untriaged |  |
| CKV_AWS_199 | Ensure Image Builder Distribution Configuration encrypts AMI's using KMS - a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_200 | Ensure that Image Recipe EBS Disk are encrypted with CMK | untriaged |  |
| CKV_AWS_201 | Ensure MemoryDB is encrypted at rest using KMS CMKs | untriaged |  |
| CKV_AWS_202 | Ensure MemoryDB data is encrypted in transit | untriaged |  |
| CKV_AWS_203 | Ensure resource is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_204 | Ensure AMIs are encrypted using KMS CMKs | untriaged |  |
| CKV_AWS_205 | Ensure to Limit AMI launch Permissions | untriaged |  |
| CKV_AWS_206 | Ensure API Gateway Domain uses a modern security Policy | untriaged |  |
| CKV_AWS_207 | Ensure MQ Broker minor version updates are enabled | untriaged |  |
| CKV_AWS_208 | Ensure MQ Broker version is current | untriaged |  |
| CKV_AWS_209 | Ensure MQ broker encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_210 | Batch job does not define a privileged container | untriaged |  |
| CKV_AWS_211 | Ensure RDS uses a modern CaCert | untriaged |  |
| CKV_AWS_212 | Ensure DMS replication instance is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_213 | Ensure ELB Policy uses only secure protocols | untriaged |  |
| CKV_AWS_214 | Ensure AppSync API Cache is encrypted at rest | untriaged |  |
| CKV_AWS_215 | Ensure AppSync API Cache is encrypted in transit | untriaged |  |
| CKV_AWS_216 | Ensure CloudFront distribution is enabled | untriaged |  |
| CKV_AWS_217 | Ensure Create before destroy for API deployments | mapped |  |
| CKV_AWS_218 | Ensure that CloudSearch is using latest TLS | untriaged |  |
| CKV_AWS_219 | Ensure CodePipeline Artifact store is using a KMS CMK | untriaged |  |
| CKV_AWS_220 | Ensure that CloudSearch is using https | untriaged |  |
| CKV_AWS_221 | Ensure CodeArtifact Domain is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_222 | Ensure DMS replication instance gets all minor upgrade automatically | untriaged |  |
| CKV_AWS_223 | Ensure ECS Cluster enables logging of ECS Exec | mapped |  |
| CKV_AWS_224 | Ensure ECS Cluster logging is enabled and client to container communication uses CMK | mapped |  |
| CKV_AWS_225 | Ensure API Gateway method setting caching is enabled | mapped |  |
| CKV_AWS_226 | Ensure DB instance gets all minor upgrades automatically | mapped |  |
| CKV_AWS_227 | Ensure KMS key is enabled | untriaged |  |
| CKV_AWS_228 | Verify Elasticsearch domain is using an up to date TLS policy | mapped |  |
| CKV_AWS_229 | Ensure no NACL allow ingress from 0.0.0.0:0 to port 21 | untriaged |  |
| CKV_AWS_230 | Ensure no NACL allow ingress from 0.0.0.0:0 to port 20 | untriaged |  |
| CKV_AWS_231 | Ensure no NACL allow ingress from 0.0.0.0:0 to port 3389 | untriaged |  |
| CKV_AWS_232 | Ensure no NACL allow ingress from 0.0.0.0:0 to port 22 | untriaged |  |
| CKV_AWS_233 | Ensure Create before destroy for ACM certificates | untriaged |  |
| CKV_AWS_234 | Verify logging preference for ACM certificates | untriaged |  |
| CKV_AWS_235 | Ensure that copied AMIs are encrypted | untriaged |  |
| CKV_AWS_236 | Ensure AMI copying uses a CMK | untriaged |  |
| CKV_AWS_237 | Ensure Create before destroy for API Gateway | mapped |  |
| CKV_AWS_238 | Ensure that GuardDuty detector is enabled | untriaged |  |
| CKV_AWS_239 | Ensure DAX cluster endpoint is using TLS | untriaged |  |
| CKV_AWS_240 | Ensure Kinesis Firehose delivery stream is encrypted | untriaged |  |
| CKV_AWS_241 | Ensure that Kinesis Firehose Delivery Streams are encrypted with CMK | untriaged |  |
| CKV_AWS_242 | Ensure MWAA environment has scheduler logs enabled | untriaged |  |
| CKV_AWS_243 | Ensure MWAA environment has worker logs enabled | untriaged |  |
| CKV_AWS_244 | Ensure MWAA environment has webserver logs enabled | untriaged |  |
| CKV_AWS_245 | Ensure replicated backups are encrypted at rest using KMS CMKs | untriaged |  |
| CKV_AWS_246 | Ensure RDS Cluster activity streams are encrypted using KMS CMKs | untriaged |  |
| CKV_AWS_247 | Ensure all data stored in the Elasticsearch is encrypted with a CMK | mapped |  |
| CKV_AWS_248 | Ensure that Elasticsearch is not using the default Security Group | mapped |  |
| CKV_AWS_249 | Ensure that the Execution Role ARN and the Task Role ARN are different in ECS Task definitions | mapped |  |
| CKV_AWS_250 | Ensure that RDS PostgreSQL instances use a non vulnerable version with the log_fdw extension (https://aws.amazon.com/security/security-bulletins/AWS-2022-004/) | untriaged |  |
| CKV_AWS_251 | Ensure CloudTrail logging is enabled | untriaged |  |
| CKV_AWS_252 | Ensure CloudTrail defines an SNS Topic | mapped |  |
| CKV_AWS_253 | Ensure DLM cross region events are encrypted | untriaged |  |
| CKV_AWS_254 | Ensure DLM cross region events are encrypted with Customer Managed Key | untriaged |  |
| CKV_AWS_255 | Ensure DLM cross region schedules are encrypted | untriaged |  |
| CKV_AWS_256 | Ensure DLM cross region schedules are encrypted using a Customer Managed Key | untriaged |  |
| CKV_AWS_257 | Ensure CodeCommit branch changes have at least 2 approvals | untriaged |  |
| CKV_AWS_258 | Ensure that Lambda function URLs AuthType is not None | untriaged |  |
| CKV_AWS_259 | Ensure CloudFront response header policy enforces Strict Transport Security | untriaged |  |
| CKV_AWS_260 | Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 | mapped |  |
| CKV_AWS_261 | Ensure HTTP HTTPS Target group defines Healthcheck | mapped |  |
| CKV_AWS_262 | Ensure Kendra index Server side encryption uses CMK | untriaged |  |
| CKV_AWS_263 | Ensure AppFlow flow uses CMK | untriaged |  |
| CKV_AWS_264 | Ensure AppFlow connector profile uses CMK | untriaged |  |
| CKV_AWS_265 | Ensure Keyspaces Table uses CMK | untriaged |  |
| CKV_AWS_266 | Ensure DB Snapshot copy uses CMK | untriaged |  |
| CKV_AWS_267 | Ensure that Comprehend Entity Recognizer's model is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_268 | Ensure that Comprehend Entity Recognizer's volume is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_269 | Ensure Connect Instance Kinesis Video Stream Storage Config uses CMK | untriaged |  |
| CKV_AWS_270 | Ensure Connect Instance S3 Storage Config uses CMK | untriaged |  |
| CKV_AWS_271 | Ensure DynamoDB table replica KMS encryption uses CMK | untriaged |  |
| CKV_AWS_272 | Ensure AWS Lambda function is configured to validate code-signing | mapped |  |
| CKV_AWS_273 | Ensure access is controlled through SSO and not AWS IAM defined users | mapped |  |
| CKV_AWS_274 | Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy | mapped |  |
| CKV_AWS_275 | Disallow policies from using the AWS AdministratorAccess policy | untriaged |  |
| CKV_AWS_276 | Ensure Data Trace is not enabled in API Gateway Method Settings | mapped |  |
| CKV_AWS_277 | Ensure no security groups allow ingress from 0.0.0.0:0 to port -1 | untriaged |  |
| CKV_AWS_278 | Ensure MemoryDB snapshot is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_279 | Ensure Neptune snapshot is securely encrypted | mapped |  |
| CKV_AWS_280 | Ensure Neptune snapshot is encrypted by KMS using a customer managed Key (CMK) | mapped |  |
| CKV_AWS_281 | Ensure RedShift snapshot copy is encrypted by KMS using a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_282 | Ensure that Redshift Serverless namespace is encrypted by KMS using a customer managed key (CMK) | untriaged |  |
| CKV_AWS_283 | Ensure no IAM policies documents allow ALL or any AWS principal permissions to the resource | mapped |  |
| CKV_AWS_284 | Ensure State Machine has X-Ray tracing enabled | untriaged |  |
| CKV_AWS_285 | Ensure State Machine has execution history logging enabled | untriaged |  |
| CKV_AWS_286 | Ensure IAM policies does not allow privilege escalation | mapped |  |
| CKV_AWS_287 | Ensure IAM policies does not allow credentials exposure | mapped |  |
| CKV_AWS_288 | Ensure IAM policies does not allow data exfiltration | mapped |  |
| CKV_AWS_289 | Ensure IAM policies does not allow permissions management / resource exposure without constraints | mapped |  |
| CKV_AWS_290 | Ensure IAM policies does not allow write access without constraints | mapped |  |
| CKV_AWS_291 | Ensure MSK nodes are private | untriaged |  |
| CKV_AWS_292 | Ensure DocumentDB Global Cluster is encrypted at rest (default is unencrypted) | untriaged |  |
| CKV_AWS_293 | Ensure that AWS database instances have deletion protection enabled | mapped |  |
| CKV_AWS_294 | Ensure CloudTrail Event Data Store uses CMK | untriaged |  |
| CKV_AWS_295 | Ensure DataSync Location Object Storage doesn't expose secrets | untriaged |  |
| CKV_AWS_296 | Ensure DMS endpoint uses Customer Managed Key (CMK) | untriaged |  |
| CKV_AWS_297 | Ensure EventBridge Scheduler Schedule uses Customer Managed Key (CMK) | untriaged |  |
| CKV_AWS_298 | Ensure DMS S3 uses Customer Managed Key (CMK) | untriaged |  |
| CKV_AWS_300 | Ensure S3 lifecycle configuration sets period for aborting failed uploads | untriaged |  |
| CKV_AWS_301 | Ensure that AWS Lambda function is not publicly accessible | untriaged |  |
| CKV_AWS_302 | Ensure DB Snapshots are not Public | untriaged |  |
| CKV_AWS_303 | Ensure SSM documents are not Public | untriaged |  |
| CKV_AWS_304 | Ensure Secrets Manager secrets should be rotated within 90 days | untriaged |  |
| CKV_AWS_305 | Ensure CloudFront distribution has a default root object configured | mapped |  |
| CKV_AWS_306 | Ensure SageMaker notebook instances should be launched into a custom VPC | untriaged |  |
| CKV_AWS_307 | Ensure SageMaker Users should not have root access to SageMaker notebook instances | untriaged |  |
| CKV_AWS_308 | Ensure API Gateway method setting caching is set to encrypted | untriaged |  |
| CKV_AWS_309 | Ensure API GatewayV2 routes specify an authorization type | untriaged |  |
| CKV_AWS_310 | Ensure CloudFront distributions should have origin failover configured | mapped |  |
| CKV_AWS_311 | Ensure that CodeBuild S3 logs are encrypted | untriaged |  |
| CKV_AWS_312 | Ensure Elastic Beanstalk environments have enhanced health reporting enabled | untriaged |  |
| CKV_AWS_313 | Ensure RDS cluster configured to copy tags to snapshots | mapped |  |
| CKV_AWS_314 | Ensure CodeBuild project environments have a logging configuration | mapped |  |
| CKV_AWS_315 | Ensure EC2 Auto Scaling groups use EC2 launch templates | untriaged |  |
| CKV_AWS_316 | Ensure CodeBuild project environments do not have privileged mode enabled | mapped |  |
| CKV_AWS_317 | Ensure Elasticsearch Domain Audit Logging is enabled | mapped |  |
| CKV_AWS_318 | Ensure Elasticsearch domains are configured with at least three dedicated master nodes for HA | mapped |  |
| CKV_AWS_319 | Ensure that CloudWatch alarm actions are enabled | untriaged |  |
| CKV_AWS_320 | Ensure Redshift clusters do not use the default database name | untriaged |  |
| CKV_AWS_321 | Ensure Redshift clusters use enhanced VPC routing | mapped |  |
| CKV_AWS_322 | Ensure ElastiCache for Redis cache clusters have auto minor version upgrades enabled | untriaged |  |
| CKV_AWS_323 | Ensure ElastiCache clusters do not use the default subnet group | untriaged |  |
| CKV_AWS_324 | Ensure that RDS Cluster log capture is enabled | mapped |  |
| CKV_AWS_325 | Ensure that RDS Cluster audit logging is enabled for MySQL engine | mapped |  |
| CKV_AWS_326 | Ensure that RDS Aurora Clusters have backtracking enabled | mapped |  |
| CKV_AWS_327 | Ensure RDS Clusters are encrypted using KMS CMKs | mapped |  |
| CKV_AWS_328 | Ensure that ALB is configured with defensive or strictest desync mitigation mode | mapped |  |
| CKV_AWS_329 | EFS access points should enforce a root directory | untriaged |  |
| CKV_AWS_330 | EFS access points should enforce a user identity | untriaged |  |
| CKV_AWS_331 | Ensure Transit Gateways do not automatically accept VPC attachment requests | untriaged |  |
| CKV_AWS_332 | Ensure ECS Fargate services run on the latest Fargate platform version | mapped |  |
| CKV_AWS_333 | Ensure ECS services do not have public IP addresses assigned to them automatically | mapped |  |
| CKV_AWS_334 | Ensure ECS containers should run as non-privileged | untriaged |  |
| CKV_AWS_335 | Ensure ECS task definitions should not share the host's process namespace | untriaged |  |
| CKV_AWS_336 | Ensure ECS containers are limited to read-only access to root filesystems | mapped |  |
| CKV_AWS_337 | Ensure SSM parameters are using KMS CMK | untriaged |  |
| CKV_AWS_338 | Ensure CloudWatch log groups retains logs for at least 1 year | mapped |  |
| CKV_AWS_339 | Ensure EKS clusters run on a supported Kubernetes version | untriaged |  |
| CKV_AWS_340 | Ensure Elastic Beanstalk managed platform updates are enabled | untriaged |  |
| CKV_AWS_341 | Ensure Launch template should not have a metadata response hop limit greater than 1 | untriaged |  |
| CKV_AWS_342 | Ensure WAF rule has any actions | untriaged |  |
| CKV_AWS_343 | Ensure Amazon Redshift clusters should have automatic snapshots enabled | untriaged |  |
| CKV_AWS_344 | Ensure that Network firewalls have deletion protection enabled | untriaged |  |
| CKV_AWS_345 | Ensure that Network firewall encryption is via a CMK | untriaged |  |
| CKV_AWS_346 | Ensure Network Firewall Policy defines an encryption configuration that uses a customer managed Key (CMK) | untriaged |  |
| CKV_AWS_347 | Ensure Neptune is encrypted by KMS using a customer managed Key (CMK) | mapped |  |
| CKV_AWS_348 | Ensure IAM root user does not have Access keys | untriaged |  |
| CKV_AWS_349 | Ensure EMR Cluster security configuration encrypts local disks | untriaged |  |
| CKV_AWS_350 | Ensure EMR Cluster security configuration encrypts EBS disks | untriaged |  |
| CKV_AWS_351 | Ensure EMR Cluster security configuration encrypts InTransit | untriaged |  |
| CKV_AWS_352 | Ensure NACL ingress does not allow all Ports | untriaged |  |
| CKV_AWS_353 | Ensure that RDS instances have performance insights enabled | mapped |  |
| CKV_AWS_354 | Ensure RDS Performance Insights are encrypted using KMS CMKs | untriaged |  |
| CKV_AWS_355 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | mapped |  |
| CKV_AWS_356 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | mapped |  |
| CKV_AWS_357 | Ensure Transfer Server allows only secure protocols | untriaged |  |
| CKV_AWS_358 | Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order | untriaged |  |
| CKV_AWS_359 | Neptune DB clusters should have IAM database authentication enabled | mapped |  |
| CKV_AWS_360 | Ensure DocumentDB has an adequate backup retention period | untriaged |  |
| CKV_AWS_361 | Ensure that Neptune DB cluster has automated backups enabled with adequate retention | mapped |  |
| CKV_AWS_362 | Neptune DB clusters should be configured to copy tags to snapshots | mapped |  |
| CKV_AWS_363 | Ensure Lambda Runtime is not deprecated | mapped |  |
| CKV_AWS_364 | Ensure that AWS Lambda function permissions delegated to AWS services are limited by SourceArn or SourceAccount | untriaged |  |
| CKV_AWS_365 | Ensure SES Configuration Set enforces TLS usage | untriaged |  |
| CKV_AWS_366 | Ensure AWS Cognito identity pool does not allow unauthenticated guest access | untriaged |  |
| CKV_AWS_367 | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt model artifacts | untriaged |  |
| CKV_AWS_368 | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt data on attached storage volume | untriaged |  |
| CKV_AWS_369 | Ensure Amazon Sagemaker Data Quality Job encrypts all communications between instances used for monitoring jobs | untriaged |  |
| CKV_AWS_370 | Ensure Amazon SageMaker model uses network isolation | untriaged |  |
| CKV_AWS_371 | Ensure Amazon SageMaker Notebook Instance only allows for IMDSv2 | untriaged |  |
| CKV_AWS_372 | Ensure Amazon SageMaker Flow Definition uses KMS for output configurations | untriaged |  |
| CKV_AWS_373 | Ensure Bedrock Agent is encrypted with a CMK | untriaged |  |
| CKV_AWS_374 | Ensure AWS CloudFront web distribution has geo restriction enabled | mapped |  |
| CKV_AWS_375 | Ensure AWS S3 bucket does not have global view ACL permissions enabled | untriaged |  |
| CKV_AWS_376 | Ensure AWS Elastic Load Balancer listener uses TLS/SSL | mapped |  |
| CKV_AWS_377 | Ensure Route 53 domains have transfer lock protection | untriaged |  |
| CKV_AWS_378 | Ensure AWS Load Balancer doesn't use HTTP protocol | mapped |  |
| CKV_AWS_379 | Ensure AWS S3 bucket is configured with secure data transport policy | mapped |  |
| CKV_AWS_380 | Ensure AWS Transfer Server uses latest Security Policy | untriaged |  |
| CKV_AWS_381 | Make sure that aws_codegurureviewer_repository_association has a CMK | untriaged |  |
| CKV_AWS_382 | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 | mapped |  |
| CKV_AWS_383 | Ensure AWS Bedrock agent is associated with Bedrock guardrails | untriaged |  |
| CKV_AWS_385 | Ensure AWS SNS topic policies do not allow cross-account access | untriaged |  |
| CKV_AWS_386 | Reduce potential for WhoAMI cloud image name confusion attack | untriaged |  |
| CKV_AWS_387 | Ensure SQS policy does not allow public access through wildcards | untriaged |  |
| CKV_AWS_388 | Ensure AWS Aurora PostgreSQL is not exposed to local file read vulnerability | untriaged |  |
| CKV_AWS_389 | Ensure AWS Auto Scaling group launch configuration doesn't have public IP address assignment enabled | untriaged |  |
| CKV_AWS_390 | Ensure AWS EMR block public access setting is enabled | untriaged |  |
| CKV_AWS_391 | Avoid AWS Redshift cluster with commonly used master username and public access setting enabled | mapped |  |
| CKV_AWS_392 | Ensure AWS S3 access point block public access setting is enabled | untriaged |  |
| CKV_AWS_393 | Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order on IAM role | untriaged |  |
| CKV_AWS_394 | Ensure aws_availability_zones data source pins zone identity so its result set does not silently expand when AWS adds an Availability Zone | untriaged |  |

## Azure

| Check | Name | Status | Reason |
|-------|------|--------|--------|
| CKV2_AZURE_1 | Ensure storage for critical data are encrypted with Customer Managed Key | untriaged |  |
| CKV2_AZURE_2 | Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account | untriaged |  |
| CKV2_AZURE_3 | Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server | untriaged |  |
| CKV2_AZURE_4 | Ensure Azure SQL server ADS VA Send scan reports to is configured | untriaged |  |
| CKV2_AZURE_5 | Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server | untriaged |  |
| CKV2_AZURE_6 | Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled | untriaged |  |
| CKV2_AZURE_7 | Ensure that Azure Active Directory Admin is configured | untriaged |  |
| CKV2_AZURE_8 | Ensure the storage container storing the activity logs is not publicly accessible | untriaged |  |
| CKV2_AZURE_9 | Ensure Virtual Machines are utilizing Managed Disks | untriaged |  |
| CKV2_AZURE_10 | Ensure that Microsoft Antimalware is configured to automatically updates for Virtual Machines | untriaged |  |
| CKV2_AZURE_11 | Ensure that Azure Data Explorer encryption at rest uses a customer-managed key | untriaged |  |
| CKV2_AZURE_12 | Ensure that virtual machines are backed up using Azure Backup | untriaged |  |
| CKV2_AZURE_13 | Ensure that sql servers enables data security policy | untriaged |  |
| CKV2_AZURE_14 | Ensure that Unattached disks are encrypted | untriaged |  |
| CKV2_AZURE_15 | Ensure that Azure data factories are encrypted with a customer-managed key | untriaged |  |
| CKV2_AZURE_16 | Ensure that MySQL server enables customer-managed key for encryption | untriaged |  |
| CKV2_AZURE_17 | Ensure that PostgreSQL server enables customer-managed key for encryption | untriaged |  |
| CKV2_AZURE_19 | Ensure that Azure Synapse workspaces have no IP firewall rules attached | untriaged |  |
| CKV2_AZURE_20 | Ensure Storage logging is enabled for Table service for read requests | untriaged |  |
| CKV2_AZURE_21 | Ensure Storage logging is enabled for Blob service for read requests | untriaged |  |
| CKV2_AZURE_22 | Ensure that Cognitive Services enables customer-managed key for encryption | untriaged |  |
| CKV2_AZURE_23 | Ensure Azure spring cloud is configured with Virtual network (Vnet) | untriaged |  |
| CKV2_AZURE_24 | Ensure Azure automation account does NOT have overly permissive network access | untriaged |  |
| CKV2_AZURE_25 | Ensure Azure SQL database Transparent Data Encryption (TDE) is enabled | untriaged |  |
| CKV2_AZURE_26 | Ensure Azure PostgreSQL Flexible server is not configured with overly permissive network access | untriaged |  |
| CKV2_AZURE_27 | Ensure Azure AD authentication is enabled for Azure SQL (MSSQL) | untriaged |  |
| CKV2_AZURE_28 | Ensure Container Instance is configured with managed identity | untriaged |  |
| CKV2_AZURE_29 | Ensure AKS cluster has Azure CNI networking enabled | untriaged |  |
| CKV2_AZURE_30 | Ensure Azure Container Registry (ACR) has HTTPS enabled for webhook | untriaged |  |
| CKV2_AZURE_31 | Ensure VNET subnet is configured with a Network Security Group (NSG) | untriaged |  |
| CKV2_AZURE_32 | Ensure private endpoint is configured to key vault | untriaged |  |
| CKV2_AZURE_33 | Ensure storage account is configured with private endpoint | untriaged |  |
| CKV2_AZURE_34 | Ensure Azure SQL server firewall is not overly permissive | untriaged |  |
| CKV2_AZURE_35 | Ensure Azure recovery services vault is configured with managed identity | untriaged |  |
| CKV2_AZURE_36 | Ensure Azure automation account is configured with managed identity | untriaged |  |
| CKV2_AZURE_37 | Ensure Azure MariaDB server is using latest TLS (1.2) | untriaged |  |
| CKV2_AZURE_38 | Ensure soft-delete is enabled on Azure storage account | untriaged |  |
| CKV2_AZURE_39 | Ensure Azure VM is not configured with public IP and serial console access | untriaged |  |
| CKV2_AZURE_40 | Ensure storage account is not configured with Shared Key authorization | untriaged |  |
| CKV2_AZURE_41 | Ensure storage account is configured with SAS expiration policy | untriaged |  |
| CKV2_AZURE_42 | Ensure Azure PostgreSQL server is configured with private endpoint | untriaged |  |
| CKV2_AZURE_43 | Ensure Azure MariaDB server is configured with private endpoint | untriaged |  |
| CKV2_AZURE_44 | Ensure Azure MySQL server is configured with private endpoint | untriaged |  |
| CKV2_AZURE_45 | Ensure Microsoft SQL server is configured with private endpoint | untriaged |  |
| CKV2_AZURE_46 | Ensure that Azure Synapse Workspace vulnerability assessment is enabled | untriaged |  |
| CKV2_AZURE_47 | Ensure storage account is configured without blob anonymous access | untriaged |  |
| CKV2_AZURE_48 | Ensure that Databricks Workspaces enables customer-managed key for root DBFS encryption | untriaged |  |
| CKV2_AZURE_49 | Ensure that Azure Machine learning workspace is not configured with overly permissive network access | untriaged |  |
| CKV2_AZURE_50 | Ensure Azure Storage Account storing Machine Learning workspace high business impact data is not publicly accessible | untriaged |  |
| CKV2_AZURE_51 | Ensure Synapse SQL Pool has a security alert policy | untriaged |  |
| CKV2_AZURE_52 | Ensure Synapse SQL Pool has vulnerability assessment attached | untriaged |  |
| CKV2_AZURE_53 | Ensure Azure Synapse Workspace has extended audit logs | untriaged |  |
| CKV2_AZURE_54 | Ensure log monitoring is enabled for Synapse SQL Pool | untriaged |  |
| CKV2_AZURE_55 | Ensure Azure Spring Cloud app end-to-end TLS is enabled | untriaged |  |
| CKV2_AZURE_56 | Ensure Azure MySQL Flexible Server is configured with private endpoint | untriaged |  |
| CKV2_AZURE_57 | Ensure PostgreSQL Flexible Server is configured with private endpoint | untriaged |  |
| CKV_AZURE_1 | Ensure Azure Instance does not use basic authentication(Use SSH Key Instead) | untriaged |  |
| CKV_AZURE_2 | Ensure Azure managed disk has encryption enabled | untriaged |  |
| CKV_AZURE_3 | Ensure that 'enable_https_traffic_only' is enabled | mapped |  |
| CKV_AZURE_4 | Ensure AKS logging to Azure Monitoring is Configured | untriaged |  |
| CKV_AZURE_5 | Ensure RBAC is enabled on AKS clusters | untriaged |  |
| CKV_AZURE_6 | Ensure AKS has an API Server Authorized IP Ranges enabled | untriaged |  |
| CKV_AZURE_7 | Ensure AKS cluster has Network Policy configured | untriaged |  |
| CKV_AZURE_8 | Ensure Kubernetes Dashboard is disabled | untriaged |  |
| CKV_AZURE_9 | Ensure that RDP access is restricted from the internet | untriaged |  |
| CKV_AZURE_10 | Ensure that SSH access is restricted from the internet | untriaged |  |
| CKV_AZURE_11 | Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) | mapped |  |
| CKV_AZURE_12 | Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' | untriaged |  |
| CKV_AZURE_13 | Ensure App Service Authentication is set on Azure App Service | untriaged |  |
| CKV_AZURE_14 | Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service | untriaged |  |
| CKV_AZURE_15 | Ensure web app is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_16 | Ensure that Register with Azure Active Directory is enabled on App Service | untriaged |  |
| CKV_AZURE_17 | Ensure the web app has 'Client Certificates (Incoming client certificates)' set | mapped |  |
| CKV_AZURE_18 | Ensure that 'HTTP Version' is the latest if used to run the web app | untriaged |  |
| CKV_AZURE_19 | Ensure that standard pricing tier is selected | untriaged |  |
| CKV_AZURE_20 | Ensure that security contact 'Phone number' is set | untriaged |  |
| CKV_AZURE_21 | Ensure that 'Send email notification for high severity alerts' is set to 'On' | untriaged |  |
| CKV_AZURE_22 | Ensure that 'Send email notification for high severity alerts' is set to 'On' | untriaged |  |
| CKV_AZURE_23 | Ensure that 'Auditing' is set to 'On' for SQL servers | untriaged |  |
| CKV_AZURE_24 | Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers | untriaged |  |
| CKV_AZURE_25 | Ensure that 'Threat Detection types' is set to 'All' | untriaged |  |
| CKV_AZURE_26 | Ensure that 'Send Alerts To' is enabled for MSSQL servers | untriaged |  |
| CKV_AZURE_27 | Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers | untriaged |  |
| CKV_AZURE_28 | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server | untriaged |  |
| CKV_AZURE_29 | Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server | untriaged |  |
| CKV_AZURE_30 | Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server | untriaged |  |
| CKV_AZURE_31 | Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server | untriaged |  |
| CKV_AZURE_32 | Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server | untriaged |  |
| CKV_AZURE_33 | Ensure Storage logging is enabled for Queue service for read, write and delete requests | untriaged |  |
| CKV_AZURE_34 | Ensure that 'Public access level' is set to Private for blob containers | untriaged |  |
| CKV_AZURE_35 | Ensure default network access rule for Storage Accounts is set to deny | mapped |  |
| CKV_AZURE_36 | Ensure 'Trusted Microsoft Services' is enabled for Storage Account access | mapped |  |
| CKV_AZURE_37 | Ensure that Activity Log Retention is set 365 days or greater | mapped |  |
| CKV_AZURE_38 | Ensure audit profile captures all the activities | mapped |  |
| CKV_AZURE_39 | Ensure that no custom subscription owner roles are created | untriaged |  |
| CKV_AZURE_40 | Ensure that the expiration date is set on all keys | untriaged |  |
| CKV_AZURE_41 | Ensure that the expiration date is set on all secrets | mapped |  |
| CKV_AZURE_42 | Ensure the key vault is recoverable | untriaged |  |
| CKV_AZURE_43 | Ensure Storage Accounts adhere to the naming rules | untriaged |  |
| CKV_AZURE_44 | Ensure Storage Account is using the latest version of TLS encryption | mapped |  |
| CKV_AZURE_45 | Ensure that no sensitive credentials are exposed in VM custom_data | mapped |  |
| CKV_AZURE_47 | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MariaDB servers | untriaged |  |
| CKV_AZURE_48 | Ensure 'public network access enabled' is set to 'False' for MariaDB servers | mapped |  |
| CKV_AZURE_49 | Ensure Azure linux scale set does not use basic authentication(Use SSH Key Instead) | mapped |  |
| CKV_AZURE_50 | Ensure Virtual Machine Extensions are not Installed | mapped |  |
| CKV_AZURE_52 | Ensure MSSQL is using the latest version of TLS encryption | mapped |  |
| CKV_AZURE_53 | Ensure 'public network access enabled' is set to 'False' for mySQL servers | mapped |  |
| CKV_AZURE_54 | Ensure MySQL is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_55 | Ensure that Azure Defender is set to On for Servers | untriaged |  |
| CKV_AZURE_56 | Ensure that function apps enables Authentication | untriaged |  |
| CKV_AZURE_57 | Ensure that CORS disallows every resource to access app services | untriaged |  |
| CKV_AZURE_58 | Ensure that Azure Synapse workspaces enables managed virtual networks | untriaged |  |
| CKV_AZURE_59 | Ensure that Storage accounts disallow public access | mapped |  |
| CKV_AZURE_61 | Ensure that Azure Defender is set to On for App Service | untriaged |  |
| CKV_AZURE_62 | Ensure function apps are not accessible from all regions | untriaged |  |
| CKV_AZURE_63 | Ensure that App service enables HTTP logging | untriaged |  |
| CKV_AZURE_64 | Ensure that Azure File Sync disables public network access | untriaged |  |
| CKV_AZURE_65 | Ensure that App service enables detailed error messages | untriaged |  |
| CKV_AZURE_66 | Ensure that App service enables failed request tracing | mapped |  |
| CKV_AZURE_67 | Ensure that 'HTTP Version' is the latest, if used to run the Function app | untriaged |  |
| CKV_AZURE_68 | Ensure that PostgreSQL server disables public network access | untriaged |  |
| CKV_AZURE_69 | Ensure that Azure Defender is set to On for Azure SQL database servers | untriaged |  |
| CKV_AZURE_70 | Ensure that Function apps is only accessible over HTTPS | untriaged |  |
| CKV_AZURE_71 | Ensure that Managed identity provider is enabled for app services | untriaged |  |
| CKV_AZURE_72 | Ensure that remote debugging is not enabled for app services | untriaged |  |
| CKV_AZURE_73 | Ensure that Automation account variables are encrypted | untriaged |  |
| CKV_AZURE_74 | Ensure that Azure Data Explorer (Kusto) uses disk encryption | untriaged |  |
| CKV_AZURE_75 | Ensure that Azure Data Explorer uses double encryption | untriaged |  |
| CKV_AZURE_76 | Ensure that Azure Batch account uses key vault to encrypt data | untriaged |  |
| CKV_AZURE_77 | Ensure that UDP Services are restricted from the Internet | untriaged |  |
| CKV_AZURE_78 | Ensure FTP deployments are disabled | untriaged |  |
| CKV_AZURE_79 | Ensure that Azure Defender is set to On for SQL servers on machines | untriaged |  |
| CKV_AZURE_80 | Ensure that 'Net Framework' version is the latest, if used as a part of the web app | untriaged |  |
| CKV_AZURE_81 | Ensure that 'PHP version' is the latest, if used to run the web app | untriaged |  |
| CKV_AZURE_82 | Ensure that 'Python version' is the latest, if used to run the web app | mapped |  |
| CKV_AZURE_83 | Ensure that 'Java version' is the latest, if used to run the web app | untriaged |  |
| CKV_AZURE_84 | Ensure that Azure Defender is set to On for Storage | mapped |  |
| CKV_AZURE_85 | Ensure that Azure Defender is set to On for Kubernetes | untriaged |  |
| CKV_AZURE_86 | Ensure that Azure Defender is set to On for Container Registries | untriaged |  |
| CKV_AZURE_87 | Ensure that Azure Defender is set to On for Key Vault | untriaged |  |
| CKV_AZURE_88 | Ensure that app services use Azure Files | untriaged |  |
| CKV_AZURE_89 | Ensure that Azure Cache for Redis disables public network access | untriaged |  |
| CKV_AZURE_91 | Ensure that only SSL are enabled for Cache for Redis | untriaged |  |
| CKV_AZURE_92 | Ensure that Virtual Machines use managed disks | untriaged |  |
| CKV_AZURE_93 | Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption | untriaged |  |
| CKV_AZURE_94 | Ensure that My SQL server enables geo-redundant backups | untriaged |  |
| CKV_AZURE_95 | Ensure that automatic OS image patching is enabled for Virtual Machine Scale Sets | untriaged |  |
| CKV_AZURE_96 | Ensure that MySQL server enables infrastructure encryption | untriaged |  |
| CKV_AZURE_97 | Ensure that Virtual machine scale sets have encryption at host enabled | untriaged |  |
| CKV_AZURE_98 | Ensure that Azure Container group is deployed into virtual network | untriaged |  |
| CKV_AZURE_99 | Ensure Cosmos DB accounts have restricted access | untriaged |  |
| CKV_AZURE_100 | Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest | untriaged |  |
| CKV_AZURE_101 | Ensure that Azure Cosmos DB disables public network access | untriaged |  |
| CKV_AZURE_102 | Ensure that PostgreSQL server enables geo-redundant backups | untriaged |  |
| CKV_AZURE_103 | Ensure that Azure Data Factory uses Git repository for source control | mapped |  |
| CKV_AZURE_104 | Ensure that Azure Data factory public network access is disabled | untriaged |  |
| CKV_AZURE_105 | Ensure that Data Lake Store accounts enables encryption | untriaged |  |
| CKV_AZURE_106 | Ensure that Azure Event Grid Domain public network access is disabled | untriaged |  |
| CKV_AZURE_107 | Ensure that API management services use virtual networks | untriaged |  |
| CKV_AZURE_108 | Ensure that Azure IoT Hub disables public network access | untriaged |  |
| CKV_AZURE_109 | Ensure that key vault allows firewall rules settings | untriaged |  |
| CKV_AZURE_110 | Ensure that key vault enables purge protection | mapped |  |
| CKV_AZURE_111 | Ensure that key vault enables soft delete | untriaged |  |
| CKV_AZURE_112 | Ensure that key vault key is backed by HSM | untriaged |  |
| CKV_AZURE_113 | Ensure that SQL server disables public network access | untriaged |  |
| CKV_AZURE_114 | Ensure that key vault secrets have "content_type" set | untriaged |  |
| CKV_AZURE_115 | Ensure that AKS enables private clusters | untriaged |  |
| CKV_AZURE_116 | Ensure that AKS uses Azure Policies Add-on | untriaged |  |
| CKV_AZURE_117 | Ensure that AKS uses disk encryption set | untriaged |  |
| CKV_AZURE_118 | Ensure that Network Interfaces disable IP forwarding | untriaged |  |
| CKV_AZURE_119 | Ensure that Network Interfaces don't use public IPs | untriaged |  |
| CKV_AZURE_120 | Ensure that Application Gateway enables WAF | untriaged |  |
| CKV_AZURE_121 | Ensure that Azure Front Door enables WAF | untriaged |  |
| CKV_AZURE_122 | Ensure that Application Gateway uses WAF in "Detection" or "Prevention" modes | untriaged |  |
| CKV_AZURE_123 | Ensure that Azure Front Door uses WAF in "Detection" or "Prevention" modes | untriaged |  |
| CKV_AZURE_124 | Ensure that Azure Cognitive Search disables public network access | untriaged |  |
| CKV_AZURE_125 | Ensures that Service Fabric use three levels of protection available | untriaged |  |
| CKV_AZURE_126 | Ensures that Active Directory is used for authentication for Service Fabric | untriaged |  |
| CKV_AZURE_127 | Ensure that My SQL server enables Threat detection policy | untriaged |  |
| CKV_AZURE_128 | Ensure that PostgreSQL server enables Threat detection policy | untriaged |  |
| CKV_AZURE_129 | Ensure that MariaDB server enables geo-redundant backups | untriaged |  |
| CKV_AZURE_130 | Ensure that PostgreSQL server enables infrastructure encryption | untriaged |  |
| CKV_AZURE_131 | Ensure that 'Security contact emails' is set | untriaged |  |
| CKV_AZURE_132 | Ensure cosmosdb does not allow privileged escalation by restricting management plane changes | untriaged |  |
| CKV_AZURE_133 | Ensure Front Door WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell | untriaged |  |
| CKV_AZURE_134 | Ensure that Cognitive Services accounts disable public network access | untriaged |  |
| CKV_AZURE_135 | Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell | untriaged |  |
| CKV_AZURE_136 | Ensure that PostgreSQL Flexible server enables geo-redundant backups | untriaged |  |
| CKV_AZURE_137 | Ensure ACR admin account is disabled | untriaged |  |
| CKV_AZURE_138 | Ensures that ACR disables anonymous pulling of images | untriaged |  |
| CKV_AZURE_139 | Ensure ACR set to disable public networking | mapped |  |
| CKV_AZURE_140 | Ensure that Local Authentication is disabled on CosmosDB | untriaged |  |
| CKV_AZURE_141 | Ensure AKS local admin account is disabled | untriaged |  |
| CKV_AZURE_142 | Ensure Machine Learning Compute Cluster Local Authentication is disabled | untriaged |  |
| CKV_AZURE_143 | Ensure AKS cluster nodes do not have public IP addresses | untriaged |  |
| CKV_AZURE_144 | Ensure that Public Access is disabled for Machine Learning Workspace | untriaged |  |
| CKV_AZURE_145 | Ensure Function app is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_146 | Ensure server parameter 'log_retention' is set to 'ON' for PostgreSQL Database Server | untriaged |  |
| CKV_AZURE_147 | Ensure PostgreSQL is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_148 | Ensure Redis Cache is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_149 | Ensure that Virtual machine does not enable password authentication | untriaged |  |
| CKV_AZURE_150 | Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0 | untriaged |  |
| CKV_AZURE_151 | Ensure Windows VM enables encryption | untriaged |  |
| CKV_AZURE_152 | Ensure Client Certificates are enforced for API management | untriaged |  |
| CKV_AZURE_153 | Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot | untriaged |  |
| CKV_AZURE_154 | Ensure the App service slot is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_155 | Ensure debugging is disabled for the App service slot | untriaged |  |
| CKV_AZURE_156 | Ensure default Auditing policy for a SQL Server is configured to capture and retain the activity logs | untriaged |  |
| CKV_AZURE_157 | Ensure that Synapse workspace has data_exfiltration_protection_enabled | untriaged |  |
| CKV_AZURE_158 | Ensure Databricks Workspace data plane to control plane communication happens over private link | untriaged |  |
| CKV_AZURE_159 | Ensure function app builtin logging is enabled | untriaged |  |
| CKV_AZURE_160 | Ensure that HTTP (port 80) access is restricted from the internet | mapped |  |
| CKV_AZURE_161 | Ensures Spring Cloud API Portal is enabled on for HTTPS | untriaged |  |
| CKV_AZURE_162 | Ensures Spring Cloud API Portal Public Access Is Disabled | untriaged |  |
| CKV_AZURE_163 | Enable vulnerability scanning for container images. | untriaged |  |
| CKV_AZURE_164 | Ensures that ACR uses signed/trusted images | untriaged |  |
| CKV_AZURE_165 | Ensure geo-replicated container registries to match multi-region container deployments. | untriaged |  |
| CKV_AZURE_166 | Ensure container image quarantine, scan, and mark images verified | untriaged |  |
| CKV_AZURE_167 | Ensure a retention policy is set to cleanup untagged manifests. | untriaged |  |
| CKV_AZURE_168 | Ensure Azure Kubernetes Cluster (AKS) nodes should use a minimum number of 50 pods. | untriaged |  |
| CKV_AZURE_169 | Ensure Azure Kubernetes Cluster (AKS) nodes use scale sets | untriaged |  |
| CKV_AZURE_170 | Ensure that AKS use the Paid Sku for its SLA | untriaged |  |
| CKV_AZURE_171 | Ensure AKS cluster upgrade channel is chosen | untriaged |  |
| CKV_AZURE_172 | Ensure autorotation of Secrets Store CSI Driver secrets for AKS clusters | untriaged |  |
| CKV_AZURE_173 | Ensure API management uses at least TLS 1.2 | untriaged |  |
| CKV_AZURE_174 | Ensure API management public access is disabled | untriaged |  |
| CKV_AZURE_175 | Ensure Web PubSub uses a SKU with an SLA | untriaged |  |
| CKV_AZURE_176 | Ensure Web PubSub uses managed identities to access Azure resources | untriaged |  |
| CKV_AZURE_177 | Ensure Windows VM enables automatic updates | untriaged |  |
| CKV_AZURE_178 | Ensure linux VM enables SSH with keys for secure communication | untriaged |  |
| CKV_AZURE_179 | Ensure VM agent is installed | untriaged |  |
| CKV_AZURE_180 | Ensure that data explorer uses Sku with an SLA | untriaged |  |
| CKV_AZURE_181 | Ensure that data explorer/Kusto uses managed identities to access Azure resources securely. | untriaged |  |
| CKV_AZURE_182 | Ensure that VNET has at least 2 connected DNS Endpoints | untriaged |  |
| CKV_AZURE_183 | Ensure that VNET uses local DNS addresses | untriaged |  |
| CKV_AZURE_184 | Ensure 'local_auth_enabled' is set to 'False' | untriaged |  |
| CKV_AZURE_185 | Ensure 'Public Access' is not Enabled for App configuration | untriaged |  |
| CKV_AZURE_186 | Ensure App configuration encryption block is set. | untriaged |  |
| CKV_AZURE_187 | Ensure App configuration purge protection is enabled | untriaged |  |
| CKV_AZURE_188 | Ensure App configuration Sku is standard | untriaged |  |
| CKV_AZURE_189 | Ensure that Azure Key Vault disables public network access | untriaged |  |
| CKV_AZURE_190 | Ensure that Storage blobs restrict public access | untriaged |  |
| CKV_AZURE_191 | Ensure that Managed identity provider is enabled for Azure Event Grid Topic | untriaged |  |
| CKV_AZURE_192 | Ensure that Azure Event Grid Topic local Authentication is disabled | untriaged |  |
| CKV_AZURE_193 | Ensure public network access is disabled for Azure Event Grid Topic | untriaged |  |
| CKV_AZURE_194 | Ensure that Managed identity provider is enabled for Azure Event Grid Domain | untriaged |  |
| CKV_AZURE_195 | Ensure that Azure Event Grid Domain local Authentication is disabled | untriaged |  |
| CKV_AZURE_196 | Ensure that SignalR uses a Paid Sku for its SLA | untriaged |  |
| CKV_AZURE_197 | Ensure the Azure CDN disables the HTTP endpoint | untriaged |  |
| CKV_AZURE_198 | Ensure the Azure CDN enables the HTTPS endpoint | untriaged |  |
| CKV_AZURE_199 | Ensure that Azure Service Bus uses double encryption | untriaged |  |
| CKV_AZURE_200 | Ensure the Azure CDN endpoint is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_201 | Ensure that Azure Service Bus uses a customer-managed key to encrypt data | untriaged |  |
| CKV_AZURE_202 | Ensure that Managed identity provider is enabled for Azure Service Bus | untriaged |  |
| CKV_AZURE_203 | Ensure Azure Service Bus Local Authentication is disabled | untriaged |  |
| CKV_AZURE_204 | Ensure 'public network access enabled' is set to 'False' for Azure Service Bus | untriaged |  |
| CKV_AZURE_205 | Ensure Azure Service Bus is using the latest version of TLS encryption | untriaged |  |
| CKV_AZURE_206 | Ensure that Storage Accounts use replication | untriaged |  |
| CKV_AZURE_207 | Ensure Azure Cognitive Search service uses managed identities to access Azure resources | untriaged |  |
| CKV_AZURE_208 | Ensure that Azure Cognitive Search maintains SLA for index updates | untriaged |  |
| CKV_AZURE_209 | Ensure that Azure Cognitive Search maintains SLA for search index queries | untriaged |  |
| CKV_AZURE_210 | Ensure Azure Cognitive Search service allowed IPS does not give public Access | untriaged |  |
| CKV_AZURE_211 | Ensure App Service plan suitable for production use | untriaged |  |
| CKV_AZURE_212 | Ensure App Service has a minimum number of instances for failover | untriaged |  |
| CKV_AZURE_213 | Ensure that App Service configures health check | untriaged |  |
| CKV_AZURE_214 | Ensure App Service is set to be always on | untriaged |  |
| CKV_AZURE_215 | Ensure API management backend uses https | untriaged |  |
| CKV_AZURE_216 | Ensure DenyIntelMode is set to Deny for Azure Firewalls | untriaged |  |
| CKV_AZURE_217 | Ensure Azure Application gateways listener that allow connection requests over HTTP | untriaged |  |
| CKV_AZURE_218 | Ensure Application Gateway defines secure protocols for in transit communication | untriaged |  |
| CKV_AZURE_219 | Ensure Firewall defines a firewall policy | untriaged |  |
| CKV_AZURE_220 | Ensure Firewall policy has IDPS mode as deny | untriaged |  |
| CKV_AZURE_221 | Ensure that Azure Function App public network access is disabled | untriaged |  |
| CKV_AZURE_222 | Ensure that Azure Web App public network access is disabled | untriaged |  |
| CKV_AZURE_223 | Ensure Event Hub Namespace uses at least TLS 1.2 | untriaged |  |
| CKV_AZURE_224 | Ensure that the Ledger feature is enabled on database that requires cryptographic proof and nonrepudiation of data integrity | untriaged |  |
| CKV_AZURE_225 | Ensure the App Service Plan is zone redundant | untriaged |  |
| CKV_AZURE_226 | Ensure ephemeral disks are used for OS disks | untriaged |  |
| CKV_AZURE_227 | Ensure that the AKS cluster encrypt temp disks, caches, and data flows between Compute and Storage resources | untriaged |  |
| CKV_AZURE_228 | Ensure the Azure Event Hub Namespace is zone redundant | untriaged |  |
| CKV_AZURE_229 | Ensure the Azure SQL Database Namespace is zone redundant | untriaged |  |
| CKV_AZURE_230 | Standard Replication should be enabled | untriaged |  |
| CKV_AZURE_231 | Ensure App Service Environment is zone redundant | untriaged |  |
| CKV_AZURE_232 | Ensure that only critical system pods run on system nodes | untriaged |  |
| CKV_AZURE_233 | Ensure Azure Container Registry (ACR) is zone redundant | untriaged |  |
| CKV_AZURE_234 | Ensure that Azure Defender for cloud is set to On for Resource Manager | untriaged |  |
| CKV_AZURE_235 | Ensure that Azure container environment variables are configured with secure values only | untriaged |  |
| CKV_AZURE_236 | Ensure that Cognitive Services accounts disable local authentication | untriaged |  |
| CKV_AZURE_237 | Ensure dedicated data endpoints are enabled. | untriaged |  |
| CKV_AZURE_238 | Ensure that all Azure Cognitive Services accounts are configured with a managed identity | untriaged |  |
| CKV_AZURE_239 | Ensure Azure Synapse Workspace administrator login password is not exposed | untriaged |  |
| CKV_AZURE_240 | Ensure Azure Synapse Workspace is encrypted with a CMK | untriaged |  |
| CKV_AZURE_241 | Ensure Synapse SQL pools are encrypted | untriaged |  |
| CKV_AZURE_242 | Ensure isolated compute is enabled for Synapse Spark pools | untriaged |  |
| CKV_AZURE_244 | Avoid the use of local users for Azure Storage unless necessary | untriaged |  |
| CKV_AZURE_245 | Ensure that Azure Container group is deployed into virtual network | untriaged |  |
| CKV_AZURE_246 | Ensure Azure AKS cluster HTTP application routing is disabled | untriaged |  |
| CKV_AZURE_247 | Ensure that Azure Cognitive Services account hosted with OpenAI is configured with data loss prevention | untriaged |  |
| CKV_AZURE_248 | Ensure that if Azure Batch account public network access in case 'enabled' then its account access must be 'deny' | untriaged |  |
| CKV_AZURE_249 | Ensure Azure GitHub Actions OIDC trust policy is configured securely | untriaged |  |
| CKV_AZURE_250 | Ensure Storage Sync Service is not configured with overly permissive network access | untriaged |  |
| CKV_AZURE_251 | Ensure Azure Virtual Machine disks are configured without public network access | untriaged |  |

## GCP

| Check | Name | Status | Reason |
|-------|------|--------|--------|
| CKV2_GCP_1 | Ensure GKE clusters are not running using the Compute Engine default service account | untriaged |  |
| CKV2_GCP_2 | Ensure legacy networks do not exist for a project | untriaged |  |
| CKV2_GCP_3 | Ensure that there are only GCP-managed service account keys for each service account | untriaged |  |
| CKV2_GCP_4 | Ensure that retention policies on log buckets are configured using Bucket Lock | untriaged |  |
| CKV2_GCP_5 | Ensure that Cloud Audit Logging is configured properly across all services and all users from a project | untriaged |  |
| CKV2_GCP_6 | Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible | untriaged |  |
| CKV2_GCP_7 | Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges | untriaged |  |
| CKV2_GCP_8 | Ensure that Cloud KMS Key Rings are not anonymously or publicly accessible | untriaged |  |
| CKV2_GCP_9 | Ensure that Container Registry repositories are not anonymously or publicly accessible | untriaged |  |
| CKV2_GCP_10 | Ensure GCP Cloud Function HTTP trigger is secured | untriaged |  |
| CKV2_GCP_11 | Ensure GCP GCR Container Vulnerability Scanning is enabled | untriaged |  |
| CKV2_GCP_12 | Ensure GCP compute firewall ingress does not allow unrestricted access to all ports | untriaged |  |
| CKV2_GCP_13 | Ensure PostgreSQL database flag 'log_duration' is set to 'on' | untriaged |  |
| CKV2_GCP_14 | Ensure PostgreSQL database flag 'log_executor_stats' is set to 'off' | untriaged |  |
| CKV2_GCP_15 | Ensure PostgreSQL database flag 'log_parser_stats' is set to 'off' | untriaged |  |
| CKV2_GCP_16 | Ensure PostgreSQL database flag 'log_planner_stats' is set to 'off' | untriaged |  |
| CKV2_GCP_17 | Ensure PostgreSQL database flag 'log_statement_stats' is set to 'off' | untriaged |  |
| CKV2_GCP_18 | Ensure GCP network defines a firewall and does not use the default firewall | untriaged |  |
| CKV2_GCP_19 | Ensure GCP Kubernetes engine clusters have 'alpha cluster' feature disabled | untriaged |  |
| CKV2_GCP_20 | Ensure MySQL DB instance has point-in-time recovery backup configured | untriaged |  |
| CKV2_GCP_21 | Ensure Vertex AI instance disks are encrypted with a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_22 | Ensure Document AI Processors are encrypted with a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_23 | Ensure Document AI Warehouse Location is configured to use a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_24 | Ensure Vertex AI endpoint uses a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_25 | Ensure Vertex AI featurestore uses a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_26 | Ensure Vertex AI tensorboard uses a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_27 | Ensure Vertex AI workbench instance disks are encrypted with a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_28 | Ensure Vertex AI workbench instances are private | untriaged |  |
| CKV2_GCP_29 | Ensure logging is enabled for Dialogflow agents | untriaged |  |
| CKV2_GCP_30 | Ensure logging is enabled for Dialogflow CX agents | untriaged |  |
| CKV2_GCP_31 | Ensure logging is enabled for Dialogflow CX webhooks | untriaged |  |
| CKV2_GCP_32 | Ensure TPU v2 is private | untriaged |  |
| CKV2_GCP_33 | Ensure Vertex AI endpoint is private | untriaged |  |
| CKV2_GCP_34 | Ensure Vertex AI index endpoint is private | untriaged |  |
| CKV2_GCP_35 | Ensure Vertex AI runtime is encrypted with a Customer Managed Key (CMK) | untriaged |  |
| CKV2_GCP_36 | Ensure Vertex AI runtime is private | untriaged |  |
| CKV2_GCP_37 | Ensure GCP compute regional forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme | untriaged |  |
| CKV2_GCP_38 | Ensure GCP compute global forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme | untriaged |  |
| CKV_GCP_1 | Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters | untriaged |  |
| CKV_GCP_2 | Ensure Google compute firewall ingress does not allow unrestricted ssh access | untriaged |  |
| CKV_GCP_3 | Ensure Google compute firewall ingress does not allow unrestricted rdp access | untriaged |  |
| CKV_GCP_4 | Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites | untriaged |  |
| CKV_GCP_6 | Ensure all Cloud SQL database instance requires all incoming connections to use SSL | mapped |  |
| CKV_GCP_7 | Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters | untriaged |  |
| CKV_GCP_8 | Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters | untriaged |  |
| CKV_GCP_9 | Ensure 'Automatic node repair' is enabled for Kubernetes Clusters | untriaged |  |
| CKV_GCP_10 | Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters | mapped |  |
| CKV_GCP_11 | Ensure that Cloud SQL database Instances are not open to the world | mapped |  |
| CKV_GCP_12 | Ensure Network Policy is enabled on Kubernetes Engine Clusters | untriaged |  |
| CKV_GCP_13 | Ensure client certificate authentication to Kubernetes Engine Clusters is disabled | mapped |  |
| CKV_GCP_14 | Ensure all Cloud SQL database instance have backup configuration enabled | untriaged |  |
| CKV_GCP_15 | Ensure that BigQuery datasets are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_16 | Ensure that DNSSEC is enabled for Cloud DNS | mapped |  |
| CKV_GCP_17 | Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC | untriaged |  |
| CKV_GCP_18 | Ensure GKE Control Plane is not public | mapped |  |
| CKV_GCP_20 | Ensure master authorized networks is set to enabled in GKE clusters | mapped |  |
| CKV_GCP_21 | Ensure Kubernetes Clusters are configured with Labels | untriaged |  |
| CKV_GCP_22 | Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image | mapped |  |
| CKV_GCP_23 | Ensure Kubernetes Cluster is created with Alias IP ranges enabled | mapped |  |
| CKV_GCP_24 | Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters | untriaged |  |
| CKV_GCP_25 | Ensure Kubernetes Cluster is created with Private cluster enabled | mapped |  |
| CKV_GCP_26 | Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network | mapped |  |
| CKV_GCP_27 | Ensure that the default network does not exist in a project | mapped |  |
| CKV_GCP_28 | Ensure that Cloud Storage bucket is not anonymously or publicly accessible | mapped |  |
| CKV_GCP_29 | Ensure that Cloud Storage buckets have uniform bucket-level access enabled | untriaged |  |
| CKV_GCP_30 | Ensure that instances are not configured to use the default service account | mapped |  |
| CKV_GCP_31 | Ensure that instances are not configured to use the default service account with full access to all Cloud APIs | untriaged |  |
| CKV_GCP_32 | Ensure 'Block Project-wide SSH keys' is enabled for VM instances | untriaged |  |
| CKV_GCP_33 | Ensure oslogin is enabled for a Project | mapped |  |
| CKV_GCP_34 | Ensure that no instance in the project overrides the project setting for enabling OSLogin(OSLogin needs to be enabled in project metadata for all instances) | untriaged |  |
| CKV_GCP_35 | Ensure 'Enable connecting to serial ports' is not enabled for VM Instance | untriaged |  |
| CKV_GCP_36 | Ensure that IP forwarding is not enabled on Instances | untriaged |  |
| CKV_GCP_37 | Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_38 | Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) | mapped |  |
| CKV_GCP_39 | Ensure Compute instances are launched with Shielded VM enabled | untriaged |  |
| CKV_GCP_40 | Ensure that Compute instances do not have public IP addresses | untriaged |  |
| CKV_GCP_41 | Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level | untriaged |  |
| CKV_GCP_42 | Ensure that Service Account has no Admin privileges | untriaged |  |
| CKV_GCP_43 | Ensure KMS encryption keys are rotated within a period of 90 days | untriaged |  |
| CKV_GCP_44 | Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level | untriaged |  |
| CKV_GCP_45 | Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level | untriaged |  |
| CKV_GCP_46 | Ensure Default Service account is not used at a project level | untriaged |  |
| CKV_GCP_47 | Ensure default service account is not used at an organization level | untriaged |  |
| CKV_GCP_48 | Ensure Default Service account is not used at a folder level | untriaged |  |
| CKV_GCP_49 | Ensure roles do not impersonate or manage Service Accounts used at project level | mapped |  |
| CKV_GCP_50 | Ensure MySQL database 'local_infile' flag is set to 'off' | untriaged |  |
| CKV_GCP_51 | Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on' | mapped |  |
| CKV_GCP_52 | Ensure PostgreSQL database 'log_connections' flag is set to 'on' | untriaged |  |
| CKV_GCP_53 | Ensure PostgreSQL database 'log_disconnections' flag is set to 'on' | untriaged |  |
| CKV_GCP_54 | Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on' | untriaged |  |
| CKV_GCP_55 | Ensure PostgreSQL database 'log_min_messages' flag is set to a valid value | untriaged |  |
| CKV_GCP_56 | Ensure PostgreSQL database 'log_temp_files flag is set to '0' | untriaged |  |
| CKV_GCP_57 | Ensure PostgreSQL database 'log_min_duration_statement' flag is set to '-1' | untriaged |  |
| CKV_GCP_58 | Ensure SQL database 'cross db ownership chaining' flag is set to 'off' | untriaged |  |
| CKV_GCP_59 | Ensure SQL database 'contained database authentication' flag is set to 'off' | untriaged |  |
| CKV_GCP_60 | Ensure Cloud SQL database does not have public IP | untriaged |  |
| CKV_GCP_61 | Enable VPC Flow Logs and Intranode Visibility | untriaged |  |
| CKV_GCP_62 | Bucket should log access | mapped |  |
| CKV_GCP_63 | Bucket should not log to itself | untriaged |  |
| CKV_GCP_64 | Ensure clusters are created with Private Nodes | untriaged |  |
| CKV_GCP_65 | Manage Kubernetes RBAC users with Google Groups for GKE | untriaged |  |
| CKV_GCP_66 | Ensure use of Binary Authorization | untriaged |  |
| CKV_GCP_68 | Ensure Secure Boot for Shielded GKE Nodes is Enabled | mapped |  |
| CKV_GCP_69 | Ensure the GKE Metadata Server is Enabled | untriaged |  |
| CKV_GCP_70 | Ensure the GKE Release Channel is set | untriaged |  |
| CKV_GCP_71 | Ensure Shielded GKE Nodes are Enabled | untriaged |  |
| CKV_GCP_72 | Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled | untriaged |  |
| CKV_GCP_73 | Ensure Cloud Armor prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell | untriaged |  |
| CKV_GCP_74 | Ensure that private_ip_google_access is enabled for Subnet | untriaged |  |
| CKV_GCP_75 | Ensure Google compute firewall ingress does not allow unrestricted FTP access | untriaged |  |
| CKV_GCP_76 | Ensure that Private google access is enabled for IPV6 | untriaged |  |
| CKV_GCP_77 | Ensure Google compute firewall ingress does not allow on ftp port | untriaged |  |
| CKV_GCP_78 | Ensure Cloud storage has versioning enabled | mapped |  |
| CKV_GCP_79 | Ensure SQL database is using latest Major version | untriaged |  |
| CKV_GCP_80 | Ensure Big Query Tables are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_81 | Ensure Big Query Datasets are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_82 | Ensure KMS keys are protected from deletion | untriaged |  |
| CKV_GCP_83 | Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_84 | Ensure Artifact Registry Repositories are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_85 | Ensure Big Table Instances are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_86 | Ensure Cloud build workers are private | untriaged |  |
| CKV_GCP_87 | Ensure Data fusion instances are private | untriaged |  |
| CKV_GCP_88 | Ensure Google compute firewall ingress does not allow unrestricted mysql access | mapped |  |
| CKV_GCP_89 | Ensure Vertex AI instances are private | untriaged |  |
| CKV_GCP_90 | Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_91 | Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_92 | Ensure Vertex AI datasets uses a CMK (Customer Managed Key) | untriaged |  |
| CKV_GCP_93 | Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (CSEK) | untriaged |  |
| CKV_GCP_94 | Ensure Dataflow jobs are private | untriaged |  |
| CKV_GCP_95 | Ensure Memorystore for Redis has AUTH enabled | untriaged |  |
| CKV_GCP_96 | Ensure Vertex AI Metadata Store uses a CMK (Customer Managed Key) | untriaged |  |
| CKV_GCP_97 | Ensure Memorystore for Redis uses intransit encryption | untriaged |  |
| CKV_GCP_98 | Ensure that Dataproc clusters are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_99 | Ensure that Pub/Sub Topics are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_100 | Ensure that BigQuery Tables are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_101 | Ensure that Artifact Registry repositories are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_102 | Ensure that GCP Cloud Run services are not anonymously or publicly accessible | untriaged |  |
| CKV_GCP_103 | Ensure Dataproc Clusters do not have public IPs | untriaged |  |
| CKV_GCP_104 | Ensure Datafusion has stack driver logging enabled | untriaged |  |
| CKV_GCP_105 | Ensure Datafusion has stack driver monitoring enabled | untriaged |  |
| CKV_GCP_106 | Ensure Google compute firewall ingress does not allow unrestricted http port 80 access | untriaged |  |
| CKV_GCP_107 | Cloud functions should not be public | untriaged |  |
| CKV_GCP_108 | Ensure hostnames are logged for GCP PostgreSQL databases | untriaged |  |
| CKV_GCP_109 | Ensure the GCP PostgreSQL database log levels are set to ERROR or lower | untriaged |  |
| CKV_GCP_110 | Ensure pgAudit is enabled for your GCP PostgreSQL database | untriaged |  |
| CKV_GCP_111 | Ensure GCP PostgreSQL logs SQL statements | untriaged |  |
| CKV_GCP_112 | Ensure KMS policy should not allow public access | untriaged |  |
| CKV_GCP_113 | Ensure IAM policy should not define public access | untriaged |  |
| CKV_GCP_114 | Ensure public access prevention is enforced on Cloud Storage bucket | untriaged |  |
| CKV_GCP_115 | Ensure basic roles are not used at organization level. | untriaged |  |
| CKV_GCP_116 | Ensure basic roles are not used at folder level. | untriaged |  |
| CKV_GCP_117 | Ensure basic roles are not used at project level. | untriaged |  |
| CKV_GCP_118 | Ensure IAM workload identity pool provider is restricted | untriaged |  |
| CKV_GCP_119 | Ensure Spanner Database has deletion protection enabled | untriaged |  |
| CKV_GCP_120 | Ensure Spanner Database has drop protection enabled | untriaged |  |
| CKV_GCP_121 | Ensure BigQuery tables have deletion protection enabled | untriaged |  |
| CKV_GCP_122 | Ensure Big Table Instances have deletion protection enabled | untriaged |  |
| CKV_GCP_123 | GKE Don't Use NodePools in the Cluster configuration | untriaged |  |
| CKV_GCP_124 | Ensure GCP Cloud Function is not configured with overly permissive Ingress setting | untriaged |  |
| CKV_GCP_125 | Ensure GCP GitHub Actions OIDC trust policy is configured securely | untriaged |  |
| CKV_GCP_126 | Ensure Vertex AI Notebook instances are launched with Shielded VM enabled | untriaged |  |
| CKV_GCP_127 | Ensure Integrity Monitoring for Shielded Vertex AI Notebook Instances is Enabled | untriaged |  |

## Kubernetes

| Check | Name | Status | Reason |
|-------|------|--------|--------|
| CKV2_K8S_1 | RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding | untriaged |  |
| CKV2_K8S_2 | Granting `create` permissions to `nodes/proxy` or `pods/exec` sub resources allows potential privilege escalation | untriaged |  |
| CKV2_K8S_3 | No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts | untriaged |  |
| CKV2_K8S_4 | ServiceAccounts and nodes that can modify services/status may set the `status.loadBalancer.ingress.ip` field to exploit the unfixed CVE-2020-8554 and launch MiTM attacks against the cluster. | untriaged |  |
| CKV2_K8S_5 | No ServiceAccount/Node should be able to read all secrets | untriaged |  |
| CKV2_K8S_6 | Minimize the admission of pods which lack an associated NetworkPolicy | mapped |  |
| CKV_K8S_1 | Do not admit containers wishing to share the host process ID namespace | untriaged |  |
| CKV_K8S_2 | Do not admit privileged containers | untriaged |  |
| CKV_K8S_3 | Do not admit containers wishing to share the host IPC namespace | untriaged |  |
| CKV_K8S_4 | Do not admit containers wishing to share the host network namespace | untriaged |  |
| CKV_K8S_5 | Containers should not run with allowPrivilegeEscalation | untriaged |  |
| CKV_K8S_6 | Do not admit root containers | untriaged |  |
| CKV_K8S_7 | Do not admit containers with the NET_RAW capability | untriaged |  |
| CKV_K8S_8 | Liveness Probe Should be Configured | mapped |  |
| CKV_K8S_9 | Readiness Probe Should be Configured | mapped |  |
| CKV_K8S_10 | CPU requests should be set | mapped |  |
| CKV_K8S_11 | CPU limits should be set | mapped |  |
| CKV_K8S_12 | Memory requests should be set | mapped |  |
| CKV_K8S_13 | Memory limits should be set | mapped |  |
| CKV_K8S_14 | Image Tag should be fixed - not latest or blank | untriaged |  |
| CKV_K8S_15 | Image Pull Policy should be Always | mapped |  |
| CKV_K8S_16 | Container should not be privileged | mapped |  |
| CKV_K8S_17 | Containers should not share the host process ID namespace | mapped |  |
| CKV_K8S_18 | Containers should not share the host IPC namespace | untriaged |  |
| CKV_K8S_19 | Containers should not share the host network namespace | mapped |  |
| CKV_K8S_20 | Containers should not run with allowPrivilegeEscalation | mapped |  |
| CKV_K8S_21 | The default namespace should not be used | untriaged |  |
| CKV_K8S_22 | Use read-only filesystem for containers where possible | mapped |  |
| CKV_K8S_23 | Minimize the admission of root containers | mapped |  |
| CKV_K8S_24 | Do not allow containers with added capability | untriaged |  |
| CKV_K8S_25 | Minimize the admission of containers with added capability | mapped |  |
| CKV_K8S_26 | Do not specify hostPort unless absolutely necessary | untriaged |  |
| CKV_K8S_27 | Do not expose the docker daemon socket to containers | untriaged |  |
| CKV_K8S_28 | Minimize the admission of containers with the NET_RAW capability | mapped |  |
| CKV_K8S_29 | Apply security context to your pods and containers | mapped |  |
| CKV_K8S_30 | Apply security context to your containers | untriaged |  |
| CKV_K8S_31 | Ensure that the seccomp profile is set to docker/default or runtime/default | mapped |  |
| CKV_K8S_32 | Ensure default seccomp profile set to docker/default or runtime/default | untriaged |  |
| CKV_K8S_33 | Ensure the Kubernetes dashboard is not deployed | untriaged |  |
| CKV_K8S_34 | Ensure that Tiller (Helm v2) is not deployed | untriaged |  |
| CKV_K8S_35 | Prefer using secrets as files over secrets as environment variables | mapped |  |
| CKV_K8S_36 | Minimize the admission of containers with capabilities assigned | untriaged |  |
| CKV_K8S_37 | Minimize the admission of containers with capabilities assigned | mapped |  |
| CKV_K8S_38 | Ensure that Service Account Tokens are only mounted where necessary | mapped |  |
| CKV_K8S_39 | Do not use the CAP_SYS_ADMIN linux capability | mapped |  |
| CKV_K8S_40 | Containers should run as a high UID to avoid host conflict | mapped |  |
| CKV_K8S_41 | Ensure that default service accounts are not actively used | untriaged |  |
| CKV_K8S_42 | Ensure that default service accounts are not actively used | untriaged |  |
| CKV_K8S_43 | Image should use digest | mapped |  |
| CKV_K8S_44 | Ensure that the Tiller Service (Helm v2) is deleted | untriaged |  |
| CKV_K8S_45 | Ensure the Tiller Deployment (Helm V2) is not accessible from within the cluster | untriaged |  |
| CKV_K8S_49 | Minimize wildcard use in Roles and ClusterRoles | untriaged |  |
| CKV_K8S_68 | Ensure that the --anonymous-auth argument is set to false | untriaged |  |
| CKV_K8S_69 | Ensure that the --basic-auth-file argument is not set | untriaged |  |
| CKV_K8S_70 | Ensure that the --token-auth-file argument is not set | untriaged |  |
| CKV_K8S_71 | Ensure that the --kubelet-https argument is set to true | untriaged |  |
| CKV_K8S_72 | Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate | untriaged |  |
| CKV_K8S_73 | Ensure that the --kubelet-certificate-authority argument is set as appropriate | untriaged |  |
| CKV_K8S_74 | Ensure that the --authorization-mode argument is not set to AlwaysAllow | untriaged |  |
| CKV_K8S_75 | Ensure that the --authorization-mode argument includes Node | untriaged |  |
| CKV_K8S_77 | Ensure that the --authorization-mode argument includes RBAC | untriaged |  |
| CKV_K8S_78 | Ensure that the admission control plugin EventRateLimit is set | untriaged |  |
| CKV_K8S_79 | Ensure that the admission control plugin AlwaysAdmit is not set | untriaged |  |
| CKV_K8S_80 | Ensure that the admission control plugin AlwaysPullImages is set | untriaged |  |
| CKV_K8S_81 | Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used | untriaged |  |
| CKV_K8S_82 | Ensure that the admission control plugin ServiceAccount is set | untriaged |  |
| CKV_K8S_83 | Ensure that the admission control plugin NamespaceLifecycle is set | untriaged |  |
| CKV_K8S_84 | Ensure that the admission control plugin PodSecurityPolicy is set | untriaged |  |
| CKV_K8S_85 | Ensure that the admission control plugin NodeRestriction is set | untriaged |  |
| CKV_K8S_86 | Ensure that the --insecure-bind-address argument is not set | untriaged |  |
| CKV_K8S_88 | Ensure that the --insecure-port argument is set to 0 | untriaged |  |
| CKV_K8S_89 | Ensure that the --secure-port argument is not set to 0 | untriaged |  |
| CKV_K8S_90 | Ensure that the --profiling argument is set to false | untriaged |  |
| CKV_K8S_91 | Ensure that the --audit-log-path argument is set | untriaged |  |
| CKV_K8S_92 | Ensure that the --audit-log-maxage argument is set to 30 or as appropriate | untriaged |  |
| CKV_K8S_93 | Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate | untriaged |  |
| CKV_K8S_94 | Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate | untriaged |  |
| CKV_K8S_95 | Ensure that the --request-timeout argument is set as appropriate | untriaged |  |
| CKV_K8S_96 | Ensure that the --service-account-lookup argument is set to true | untriaged |  |
| CKV_K8S_97 | Ensure that the --service-account-key-file argument is set as appropriate | untriaged |  |
| CKV_K8S_99 | Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate | untriaged |  |
| CKV_K8S_100 | Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate | untriaged |  |
| CKV_K8S_102 | Ensure that the --etcd-cafile argument is set as appropriate | untriaged |  |
| CKV_K8S_104 | Ensure that encryption providers are appropriately configured | untriaged |  |
| CKV_K8S_105 | Ensure that the API Server only makes use of Strong Cryptographic Ciphers | untriaged |  |
| CKV_K8S_106 | Ensure that the --terminated-pod-gc-threshold argument is set as appropriate | untriaged |  |
| CKV_K8S_107 | Ensure that the --profiling argument is set to false | untriaged |  |
| CKV_K8S_108 | Ensure that the --use-service-account-credentials argument is set to true | untriaged |  |
| CKV_K8S_110 | Ensure that the --service-account-private-key-file argument is set as appropriate | untriaged |  |
| CKV_K8S_111 | Ensure that the --root-ca-file argument is set as appropriate | untriaged |  |
| CKV_K8S_112 | Ensure that the RotateKubeletServerCertificate argument is set to true | untriaged |  |
| CKV_K8S_113 | Ensure that the --bind-address argument is set to 127.0.0.1 | untriaged |  |
| CKV_K8S_114 | Ensure that the --profiling argument is set to false | untriaged |  |
| CKV_K8S_115 | Ensure that the --bind-address argument is set to 127.0.0.1 | untriaged |  |
| CKV_K8S_116 | Ensure that the --cert-file and --key-file arguments are set as appropriate | untriaged |  |
| CKV_K8S_117 | Ensure that the --client-cert-auth argument is set to true | untriaged |  |
| CKV_K8S_118 | Ensure that the --auto-tls argument is not set to true | untriaged |  |
| CKV_K8S_119 | Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate | untriaged |  |
| CKV_K8S_121 | Ensure that the --peer-client-cert-auth argument is set to true | untriaged |  |
| CKV_K8S_138 | Ensure that the --anonymous-auth argument is set to false | untriaged |  |
| CKV_K8S_139 | Ensure that the --authorization-mode argument is not set to AlwaysAllow | untriaged |  |
| CKV_K8S_140 | Ensure that the --client-ca-file argument is set as appropriate | untriaged |  |
| CKV_K8S_141 | Ensure that the --read-only-port argument is set to 0 | untriaged |  |
| CKV_K8S_143 | Ensure that the --streaming-connection-idle-timeout argument is not set to 0 | untriaged |  |
| CKV_K8S_144 | Ensure that the --protect-kernel-defaults argument is set to true | untriaged |  |
| CKV_K8S_145 | Ensure that the --make-iptables-util-chains argument is set to true | untriaged |  |
| CKV_K8S_146 | Ensure that the --hostname-override argument is not set | untriaged |  |
| CKV_K8S_147 | Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture | untriaged |  |
| CKV_K8S_148 | Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate | untriaged |  |
| CKV_K8S_149 | Ensure that the --rotate-certificates argument is not set to false | untriaged |  |
| CKV_K8S_151 | Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers | untriaged |  |
| CKV_K8S_152 | Prevent NGINX Ingress annotation snippets which contain LUA code execution. See CVE-2021-25742 | untriaged |  |
| CKV_K8S_153 | Prevent All NGINX Ingress annotation snippets. See CVE-2021-25742 | untriaged |  |
| CKV_K8S_154 | Prevent NGINX Ingress annotation snippets which contain alias statements See CVE-2021-25742 | untriaged |  |
| CKV_K8S_155 | Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations | untriaged |  |
| CKV_K8S_156 | Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests | untriaged |  |
| CKV_K8S_157 | Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings | untriaged |  |
| CKV_K8S_158 | Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles | untriaged |  |
| CKV_K8S_159 | Limit the use of git-sync to prevent code injection | untriaged |  |

## Terraform (cloud-agnostic)

| Check | Name | Status | Reason |
|-------|------|--------|--------|
| CKV_TF_1 | Ensure Terraform module sources use a commit hash | mapped |  |
| CKV_TF_2 | Ensure Terraform module sources use a tag with a version number | mapped |  |
