# Cyber-eto Qualifications 2025 - Docker CTF Challenge Writeup

## Challenge Description

**Challenge Name:** Docker  
**Category:** Forensics/OSINT  
**Flag Format:** `cybereto{part1_part2}`

Our company works with multiple microservices and deploys them in Docker containers. During development of one of our services, a developer accidentally leaked sensitive data in the source code, and later tried to remove it before building a Docker image. Your task is to analyze the Docker image, investigate it to recover the full flag.

## Initial Analysis

The challenge provides a Docker directory containing what appears to be an exported Docker image in OCI format. Let's start by examining the structure:

```bash
$ ls -la
total 32
drwx------@  7 laith  staff   224  1 تشرين الثاني 12:49 .
drwxr-xr-x  10 laith  staff   320  1 تشرين الثاني 12:50 ..
drwxr-xr-x@  3 laith  staff    96 12 أيلول        12:23 blobs
-rw-r--r--@  1 laith  staff   365 12 أيلول        12:24 index.json
-rw-r--r--@  1 laith  staff  1989  1 كانون الثاني  1970 manifest.json
-rw-r--r--@  1 laith  staff    31  1 كانون الثاني  1970 oci-layout
-rw-r--r--@  1 laith  staff    91  1 كانون الثاني  1970 repositories
```

This is clearly a Docker image export with OCI format containing:
- `blobs/` directory with image layers
- `manifest.json` with image metadata
- `index.json` and `repositories` for image references

## Docker Image Analysis

### Step 1: Examining Image Metadata

First, let's check the manifest and repositories to understand the image structure:

```bash
$ cat repositories
{"etochall":{"latest":"609d4b3e80571cef59c62188d49ea82c2c8af0dca37a23616589fba81e5170da"}}
```

The image is named `etochall:latest`. Let's look at the manifest:

```json
[{"Config":"blobs/sha256/277357379dc471b60fbcb35a54d7e8e0ba0f2098022d14bc4d0583d6e0fdd706","RepoTags":["etochall:latest"],"Layers":["blobs/sha256/dc6eb6dad5f9e332f00af553440e857b1467db1be43dd910cdb6830ba0898d50","blobs/sha256/4255cd04fbe212c10cc38e2f3d3fa696b0f3e30736c6531d600b03d79f0c1470","blobs/sha256/0e04e75dead42986f9cb52fba72e140af89ce92c81ee46d127747292d556c6d9","blobs/sha256/bbd0f067af26d818961c683a74160986ee849a11e639a9408ab54a991c69813a","blobs/sha256/6cc81cd5cd503747d46df1e0c8d1c1e0f1b7e97e142257c7e7ca65a1e5bd02ad","blobs/sha256/609d4b3e80571cef59c62188d49ea82c2c8af0dca37a23616589fba81e5170da"]}]
```

The image has 6 layers. Let's examine the image configuration to understand the build history.

### Step 2: Docker Image History Analysis

Looking at the image config file (`blobs/sha256/277357379dc471b60fbcb35a54d7e8e0ba0f2098022d14bc4d0583d6e0fdd706`):

```json
{
  "history": [
    // ... base Ubuntu layers ...
    {
      "created": "2025-09-12T12:23:50.443538836+03:00",
      "created_by": "RUN /bin/sh -c echo \"RVZFTl9JRl9FTkN9\" > /myfault.txt # buildkit",
      "comment": "buildkit.dockerfile.v0"
    },
    {
      "created": "2025-09-12T12:23:51.243711173+03:00",
      "created_by": "RUN /bin/sh -c rm /myfault.txt # buildkit",
      "comment": "buildkit.dockerfile.v0"
    }
  ]
}
```

🎯 **First Discovery!** The Docker history shows that:
1. A file `/myfault.txt` was created with content `RVZFTl9JRl9FTkN9`
2. The file was immediately deleted in the next layer

Let's decode this base64 string:

```bash
$ echo "RVZFTl9JRl9FTkN9" | base64 -d
EVEN_IF_ENC}
```

This looks like the second part of our flag! The format suggests `cybereto{part1_part2}`, so we have `part2 = EVEN_IF_ENC}`.

### Step 3: Layer Analysis and File Recovery

Even though the file was deleted, Docker layers are additive - the file still exists in the layer where it was created. Let's examine the layers:

```bash
$ ls -la blobs/sha256/
# ... various layer files ...
-rw-r--r--@  1 laith  staff       2048 12 أيلول        12:23 6cc81cd5cd503747d46df1e0c8d1c1e0f1b7e97e142257c7e7ca65a1e5bd02ad
-rw-r--r--@  1 laith  staff       1536 12 أيلول        12:23 609d4b3e80571cef59c62188d49ea82c2c8af0dca37a23616589fba81e5170da
```

Let's check what's in these layers:

```bash
$ tar -tf blobs/sha256/6cc81cd5cd503747d46df1e0c8d1c1e0f1b7e97e142257c7e7ca65a1e5bd02ad
myfault.txt

$ tar -tf blobs/sha256/609d4b3e80571cef59c62188d49ea82c2c8af0dca37a23616589fba81e5170da
.wh.myfault.txt
```

Perfect! Layer `6cc81cd5cd503747d46df1e0c8d1c1e0f1b7e97e142257c7e7ca65a1e5bd02ad` contains the file, and layer `609d4b3e80571cef59c62188d49ea82c2c8af0dca37a23616589fba81e5170da` contains the whiteout file (`.wh.myfault.txt`) indicating deletion.

Let's extract and verify the content:

```bash
$ tar -xf blobs/sha256/6cc81cd5cd503747d46df1e0c8d1c1e0f1b7e97e142257c7e7ca65a1e5bd02ad
$ cat myfault.txt
RVZFTl9JRl9FTkN9
```

Confirmed! We have the second part of the flag.

## Git Repository Analysis

Looking at the Docker layers, we can see there's a complete Git repository included in the image. Let's extract the layer containing the application files:

```bash
$ tar -tf blobs/sha256/bbd0f067af26d818961c683a74160986ee849a11e639a9408ab54a991c69813a | head -20
app/
app/.copier/
app/.copier/.copier-answers.yml.jinja
app/.copier/update_dotenv.py
app/.env
app/.git/
app/.git/COMMIT_EDITMSG
app/.git/HEAD
app/.git/branches/
app/.git/config
# ... full git repository structure ...
```

Let's extract this layer and examine the Git history:

```bash
$ tar -xf blobs/sha256/bbd0f067af26d818961c683a74160986ee849a11e639a9408ab54a991c69813a
$ cd app && git log --oneline | head -10
d4baae53 📝 credintials updated
81b45c59 📝 Update secret note
42c20c0f  Upgrade backend to the latest version (#1861)
e5132c56 📝 Update important note
2229dd9e 📝 Update release notes
73e8939f 🔧 Add  to log output directly to Docker (#1379)
9a525b26 📝 Update important note
632c09e7 📝 Update release notes
# ...
```

Several commits look suspicious, especially ones mentioning "credentials," "secret note," and "important note."

### Step 4: Git History Investigation

Let's examine the commits that might contain sensitive information:

#### Commit: 📝 Update secret note

```bash
$ git show 81b45c59
commit 81b45c5985052de3850085b8e1bfce062a8fb601
Author: qays <qays4738@gmail.com>
Date:   Wed Sep 10 21:33:41 2025 +0300

    📝 Update secret note

diff --git a/backend/app/initial_data.py b/backend/app/initial_data.py
index d806c3d3..13a0e574 100644
--- a/backend/app/initial_data.py
+++ b/backend/app/initial_data.py
@@ -18,6 +18,8 @@ def main() -> None:
     init()
     logger.info("Initial data created")
 
+def secondpart()
+    print("layers are good idea to search")
 
 if __name__ == "__main__":
     main()
```

Interesting! A function called `secondpart()` was added with the message "layers are good idea to search" - this is clearly a hint pointing us to examine the Docker layers, which we already did.

#### Searching for Base64 Encoded Secrets

Let's search the Git history for any base64-encoded strings:

```bash
$ git log --all --full-history -p | grep -E "^[+-].*[A-Za-z0-9+/]{20,}={0,2}$"
-FIRST_SUPERUSER_PASSWORD=nextCommitIwillApply
+FIRST_SUPERUSER_PASSWORD=bmFhYWFhYWFhYWFhYWFhYWEgYnJvb29vb28gdHJ5IGhhcmRlcg==
# ... more results ...
```

Let's decode this base64 string:

```bash
$ echo "bmFhYWFhYWFhYWFhYWFhYWEgYnJvb29vb28gdHJ5IGhhcmRlcg==" | base64 -d
naaaaaaaaaaaaaaaa broooooo try harder
```

This is just a taunting message from the developer, not our flag.

#### The Key Discovery: HTML Comment

Let's examine commit `42c20c0f` which shows modification to an HTML template:

```bash
$ git show 42c20c0f
commit 42c20c0f0e9741bdc0e67e4ac89e8b22df189c20
Author: qays <qays4738@gmail.com>
Date:   Wed Sep 10 21:31:54 2025 +0300

     Upgrade backend to the latest version (#1861)

diff --git a/backend/app/email-templates/build/hey.html b/backend/app/email-templates/build/hey.html
# ... large HTML diff ...
-Password: <!--Y3liZXJldG97R0lUXyFOT1RfU0VDVVJF --> {{ password }}
+Password:  {{ password }}
# ... more changes ...
```

🎯 **Second Discovery!** There's a base64-encoded comment that was removed: `Y3liZXJldG97R0lUXyFOT1RfU0VDVVJF`

Let's decode it:

```bash
$ echo "Y3liZXJldG97R0lUXyFOT1RfU0VDVVJF" | base64 -d
cybereto{GIT_!NOT_SECURE
```

Perfect! This is the first part of our flag: `cybereto{GIT_!NOT_SECURE`

## Flag Assembly

Now we have both parts of the flag:

- **Part 1** (from Git history HTML comment): `cybereto{GIT_!NOT_SECURE`
- **Part 2** (from Docker layer): `EVEN_IF_ENC}`

## Final Flag

**Flag:** `cybereto{GIT_!NOT_SECURE_EVEN_IF_ENC}`

## Key Lessons Learned

This challenge demonstrates several important security concepts:

1. **Docker Layer Persistence**: Even when files are deleted in subsequent layers, they remain accessible in the layer where they were originally created.

2. **Git History Immutability**: Sensitive data committed to Git remains in the history even after being "removed" in later commits.

3. **Multi-Stage Attacks**: The flag was split across two different hiding places (Docker layers and Git history), requiring thorough investigation.

4. **Developer Mistakes**: The challenge simulates real-world scenarios where developers accidentally commit secrets and then try to cover their tracks insufficiently.

## Tools and Techniques Used

- **Docker Image Analysis**: Examining OCI format structure, manifests, and layer contents
- **Git Forensics**: Analyzing commit history, diffs, and searching for patterns
- **Base64 Decoding**: Decoding obfuscated data found in various locations
- **File Recovery**: Extracting deleted files from Docker layers
- **Pattern Recognition**: Identifying suspicious commits and base64-encoded strings

## Timeline of Investigation

1. **Initial Reconnaissance**: Identified Docker image structure and basic metadata
2. **Docker History Analysis**: Found evidence of created and deleted `myfault.txt` 
3. **Layer Extraction**: Recovered the deleted file containing part 2 of the flag
4. **Git Repository Discovery**: Found complete Git history in Docker layers
5. **Commit Analysis**: Examined suspicious commits for secrets
6. **Pattern Searching**: Searched for base64-encoded strings in Git history
7. **HTML Template Investigation**: Found hidden comment with part 1 of the flag
8. **Flag Assembly**: Combined both parts to form the complete flag

This challenge excellently demonstrates why proper secrets management, `.gitignore` configuration, and Docker image security scanning are crucial in real-world development workflows.