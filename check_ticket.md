GCP: Implement Cloud Storage “Enable Data Access Audit Logs” Check (TrendMicro Conformity)

Description

Create a Prowler check for Cloud Storage buckets to ensure that data access audit logs are enabled. According to Trend Micro Conformity, buckets should log data access (read / write) operations so that activity on objects in the buckets can be audited for security and compliance purposes.

Trend Micro Check URL:  
https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudStorage/enable-data-access-audit-logs.html

Technical Notes

Use Prowler’s GCP API reference and guidelines for working with GCP audit log settings:  
https://docs.prowler.com/projects/prowler-open-source/en/latest/developer-guide/gcp-details/  

Follow Prowler’s check implementation guide:  
https://docs.prowler.com/projects/prowler-open-source/en/latest/developer-guide/checks/  

Use the metadata standards defined in Prowler:  
https://docs.prowler.com/projects/prowler-open-source/en/latest/developer-guide/check-metadata-guidelines/  
