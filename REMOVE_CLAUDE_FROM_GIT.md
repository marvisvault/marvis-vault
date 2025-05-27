# Instructions for Removing .claude from Git History

## Overview
The `.claude` folder contains AI assistant artifacts that should not be included in your repository. Follow these instructions to remove it from Git history completely.

## Step 1: Check if .claude is in your repository

First, check if `.claude` has been committed:

```bash
git ls-files | grep -E "^\.claude/"
```

If this returns results, `.claude` is in your Git history and needs to be removed.

## Step 2: Remove .claude from the current working tree

```bash
git rm -r --cached .claude
```

This removes `.claude` from Git's index but keeps it in your local filesystem.

## Step 3: Commit the removal

```bash
git commit -m "Remove .claude directory from repository"
```

## Step 4: Remove .claude from entire Git history (if needed)

If `.claude` was previously committed and you want to remove it from all history:

### Option A: Using git filter-branch (traditional method)

```bash
git filter-branch --force --index-filter \
  "git rm -r --cached --ignore-unmatch .claude" \
  --prune-empty --tag-name-filter cat -- --all
```

### Option B: Using git filter-repo (recommended, faster)

First install git-filter-repo if you don't have it:
```bash
pip install git-filter-repo
```

Then run:
```bash
git filter-repo --path .claude --invert-paths
```

## Step 5: Force push to remote (if repository is already pushed)

**WARNING**: This rewrites history. Coordinate with your team before doing this.

```bash
git push origin --force --all
git push origin --force --tags
```

## Step 6: Clean up local repository

```bash
git for-each-ref --format="delete %(refname)" refs/original | git update-ref --stdin
git reflog expire --expire=now --all
git gc --prune=now
```

## Prevention

The `.gitignore` file has been updated to include `.claude/`, which will prevent it from being accidentally committed in the future.

## For Team Members

If other team members have cloned the repository, they should:

1. Backup any local changes
2. Re-clone the repository fresh, OR
3. Reset their local repository:
   ```bash
   git fetch origin
   git reset --hard origin/main
   git clean -fd
   ```

## Verification

After completing these steps, verify that `.claude` is no longer in the repository:

```bash
git ls-files | grep -E "^\.claude/"  # Should return nothing
ls -la | grep claude  # Should show .claude exists locally but with no git tracking
```