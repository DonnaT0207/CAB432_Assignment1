Assignment 2 - Cloud Services Exercises - Response to Criteria
================================================

Instructions
------------------------------------------------
- Keep this file named A2_response_to_criteria.md, do not change the name
- Upload this file along with your code in the root directory of your project
- Upload this file in the current Markdown format (.md extension)
- Do not delete or rearrange sections.  If you did not attempt a criterion, leave it blank
- Text inside [ ] like [eg. S3 ] are examples and should be removed


Overview
------------------------------------------------

- **Name:** Yixuan Tang
- **Student number:** n11476290
- **Partner name (if applicable):** Ya-Sin Lin (n11145862)
- **Application name:** Video-api
- **Two line description:** We implemented this cloud-based video processing application that allows users to upload, transcode, and download videos with authentication and access control. The system integrates S3, RDS, and EFS for persistence, Cognito for identity, and additional AWS services for configuration and secrets management.
- **EC2 instance name or ID:** ec2-qut-n11145862-assessment

------------------------------------------------

### Core - First data persistence service

- **AWS service name:** Amazon S3
- **What data is being stored?:** Video files (original uploaded file and final transcoded outputs)
- **Why is this service suited to this data?:** S3 is designed for storing large binary files with durability and scalability, ideal for video storage and distribution.
- **Why is are the other services used not suitable for this data?:** RDS and DynamoDB are optimised for structured data, not large media objects. EFS is good for temporary working files, not long-term storage and public distribution.
- **Bucket/instance/table name:** n11145862-test
- **Video timestamp:** 0.01
- **Relevant files:**
    - index.js

### Core - Second data persistence service

- **AWS service name:** Amazon RDS (PostgreSQL)
- **What data is being stored?:** User accounts, video metadata, balances, and file records
- **Why is this service suited to this data?:** RDS provides strong relational queries and consistency guarantees, which are necessary for structured metadata such as user balances, file ownership, and access records.
- **Why is are the other services used not suitable for this data?:** S3 cannot store relational metadata, and EFS is unsuitable for transactional records.
- **Bucket/instance/table name:** video-api-db
- **Video timestamp:** 1.16
- **Relevant files:**
    - db.js
    - index.js

### Third data service

- **AWS service name:** Amazon EFS
- **What data is being stored?:** Temporary and intermediate working files such as transcode outputs, thumbnails, and cached job files.
- **Why is this service suited to this data?:** EFS provides a shared, low-latency file system accessible across EC2 instances, making it ideal for concurrent processing workflows.
- **Why is are the other services used not suitable for this data?:** S3 is optimised for object storage but too slow for intermediate processing. RDS is structured storage, not designed for large binary or temporary files.
- **Bucket/instance/table name:** n11476290_A2, mount path /mnt/efs/video-api
- **Video timestamp:** 2.02
- **Relevant files:**
    - index.js

### S3 Pre-signed URLs

- **S3 Bucket names:** n11145862-test
- **Video timestamp:** 3.17
- **Relevant files:**
    - index.js

### In-memory cache

- **ElastiCache instance name:** n11145862a2
- **What data is being cached?:** Frequently queried RDS metadata and job status results
- **Why is this data likely to be accessed frequently?:** Users repeatedly check video processing status and metadata, so caching reduces database load.
- **Video timestamp:** 4.01
- **Relevant files:**
    - index.js

### Core - Statelessness

- **What data is stored within your application that is not stored in cloud data services?:** Only temporary processing state in memory (ffmpeg processes, intermediate tmp files).
- **Why is this data not considered persistent state?:** All temporary files can be recreated from S3 source if lost.
- **How does your application ensure data consistency if the app suddenly stops?:** Persistent data, including uploads, metadata, and final outputs, are always stored in S3, RDS, and optionally EFS. Temporary files required during processing are stored in EFS until the task completes; after uploading outputs to cloud storage, EFS is cleared. On application restart, any remaining temporary files in EFS or local directories are removed to ensure a clean state.

Users can resume incomplete jobs via the dedicated endpoint /resume/:jobId, which reprocesses tasks using metadata from RDS and source files from S3.
- **Relevant files:**
    - index.js

### Graceful handling of persistent connections

- **Type of persistent connection and use:** [eg. server-side-events for progress reporting]
- **Method for handling lost connections:** [eg. client responds to lost connection by reconnecting and indicating loss of connection to user until connection is re-established ]
- **Relevant files:**
    -


### Core - Authentication with Cognito

- **User pool name:** n11476290-assignment2
- **How are authentication tokens handled by the client?:** Tokens are returned by the login endpoint and stored client-side (ID token used in headers for API requests).
- **Video timestamp:** 5.02
- **Relevant files:**
    - index.js
    - index.html

### Cognito multi-factor authentication

- **What factors are used for authentication:** Password + TOTP software token (Authenticator APP)
- **Video timestamp:** 5.45
- **Relevant files:**
    - index.js

### Cognito federated identities

- **Identity providers used:**
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito groups

- **How are groups used to set permissions?:** Users in the Admin group can view and manage all uploaded files. Normal users can only access their own uploads.
- **Video timestamp:** 6.39
- **Relevant files:**
    - index.js
    - index.html

### Core - DNS with Route53

- **Subdomain**:  n11145862.a2.cab432.com
- **Video timestamp:** 7.12

### Parameter store

- **Parameter names:** /n11145862/assessment2_parameter
- **Video timestamp:** 7.18
- **Relevant files:**
    - index.js
    - .env

### Secrets manager

- **Secrets names:** n11145862-a2
- **Video timestamp:** 7.42
- **Relevant files:**
    - index.js
    - .env

### Infrastructure as code

- **Technology used:** 
- **Services deployed:** 
- **Video timestamp:**
- **Relevant files:**
    - 

### Other (with prior approval only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior permission only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -