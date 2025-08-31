Assignment 1 - REST API Project - Response to Criteria
================================================

Overview
------------------------------------------------

- **Name:** Yixuan Tang
- **Student number:** n11476290
- **Application name:** video-api
- **Two line description:** A JWT-protected REST API for video processing. Users can upload videos, transcode to MP4/720p, fetch subtitles from OpenSubtitles, cache .srt, and embed a switchable subtitle track into the output MP4. Includes a simple web client.


Core criteria
------------------------------------------------

### Containerise the app

- **ECR Repository name:** video-api
- **Video timestamp:**
- **Relevant files:**
    - Dockerfile
    - .dockerignore

### Deploy the container

- **EC2 instance ID:** i-0afadc116310db5a0
- **Video timestamp:**

### User login

- **One line description:** Username/password → /login issues JWT; all file/video endpoints require Authorization: Bearer <token>. Demo users: admin/admin123, user/user123.
- **Video timestamp:**
- **Relevant files:**
    - index.js

### REST API

- **One line description:** RESTful endpoints for upload/list/search/sort/paginate, subtitle fetch, transcode and download, with proper 401/404/502 handling.
- **Video timestamp:**
- **Relevant files:**
    - index.js
    - public/index.html

### Data types

- **One line description:** Structured rows in SQLite plus semi-structured JSON metadata; binary large objects stored on disk.
- **Video timestamp:**
- **Relevant files:**
    - index.js
    - data/app.db (runtime)
    - public/index.html

#### First kind

- **One line description:** File records for uploaded videos.
- **Type:** Structured (SQLite table files, indexed by uploaded_at)
- **Rationale:** Stable schema for core attributes (id, original_name, stored_path, mime, size, uploaded_at, ext)
- **Video timestamp:**
- **Relevant files:**
    - index.js (DB schema creation)

#### Second kind

- **One line description:** Flexible metadata such as subtitles search results and cached .srt path.
- **Type:** Semi-structured JSON stored in files.ext_meta
- **Rationale:** Extensible; stores opensubtitles.query/languages/top.srt_path, etc. without schema migrations.
- **Video timestamp:**
- **Relevant files:**
  - index.js

### CPU intensive task

 **One line description:** Transcoding to MP4 720p via ffmpeg (libx264, crf=23, preset=veryfast, scale='min(1280,iw)':-2); attaches mov_text subtitle track if available.
- **Video timestamp:** 
- **Relevant files:**
    - index.js (transcode route)
    - public/index.html (Transcode button)

### CPU load testing

 **One line description:** Trigger multiple concurrent transcodes and observe CPU usage in htop/Docker charts.
- **Video timestamp:** 
- **Relevant files:**
    - loadtest.js

Additional criteria
------------------------------------------------

### Extensive REST API features

- **One line description:** Pagination, search, and sorting for files; robust error handling (401/404/502); streaming downloads; JWT auth on all data-modifying routes.
- **Video timestamp:**
- **Relevant files:**
    - index.js
    - public/index.html

### External API(s)

- **One line description:** OpenSubtitles v1 integration — search by video name, select best match, POST /download for direct link, cache .srt, and attach on transcode; graceful degrade on 403.
- **Video timestamp:**
- **Relevant files:**
    - index.js

### Additional types of data

- **One line description:** Binary video assets (uploads/outputs) and text subtitle files (.srt) stored on disk with paths referenced from DB JSON.
- **Video timestamp:**
- **Relevant files:**
    - runtime data/uploads/
    - data/outputs/
    - data/subtitles/

### Custom processing

- **One line description:** Subs → download → cache → transcode attach” processing chain with best-match selection and fallback when API unavailable.
- **Video timestamp:**
- **Relevant files:**
    - index.js

### Infrastructure as code

- **One line description:** Containerisation via Dockerfile and optional docker-compose.yml; images published to ECR (not using Terraform/CFN for cloud resources).
- **Video timestamp:**
- **Relevant files:**
    - Dockerfile
    - .dockerignore
    - docker-compose.yml

### Web client

- **One line description:** Minimal single-page client for login, upload, list/search/sort, subtitles fetch, metadata view, transcode and downloads.
- **Video timestamp:**
- **Relevant files:**
    -   public/index.html

### Upon request

- **One line description:** Not attempted
- **Video timestamp:**
- **Relevant files:**
    - 
