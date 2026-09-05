# Cloudflare R2 Setup

## Outcome

V1 uses Cloudflare only for candidate storage and public distribution:

```text
private candidate bucket  -> GitHub checks and owner review
public release bucket     -> direct custom-domain downloads
```

No Worker, Pages project, D1 database, Queue, Durable Object, AI Gateway, Workers AI deployment, or Cloudflare Tunnel is required.

## Bootstrap status (2026-09-01)

Wrangler is authenticated to the intended Cloudflare account and the active `avnxmcp.org` zone has been identified. R2 returned Cloudflare error `10042` because R2 has not been enabled for the account. Therefore neither bucket, the custom domain, nor R2 API credentials have been created yet. Publication must remain fail-closed for the `r2` host until the owner enables R2 in the Cloudflare dashboard and the verification checklist below passes.

Publication is not blocked on R2 for the interim: `sb-models publish --host github-release` (`docs/publishing-interface-v1.md`) uploads to a GitHub Release, re-verifies every object by re-download, and signs and attaches the catalog exactly as this document's upload order and verification rules describe, just with GitHub Releases standing in for the two R2 buckets below. Moving to `--host r2` once this checklist passes does not change the catalog schema, the receipt shape, or the consumer contract.

Useful official references:

- [R2 authentication and bucket-scoped tokens](https://developers.cloudflare.com/r2/api/tokens/)
- [R2 public buckets and custom domains](https://developers.cloudflare.com/r2/buckets/public-buckets/)
- [R2 pricing](https://developers.cloudflare.com/r2/pricing/)
- [R2 limits and multipart thresholds](https://developers.cloudflare.com/r2/platform/limits/)
- [R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/)
- [Cloudflare cache size limits](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)

## Owner prerequisites

- A Cloudflare account with R2 enabled.
- A domain managed in the same Cloudflare account.
- Administrator access to this GitHub repository.
- Production hostname `models.avnxmcp.org`, using the account's active `avnxmcp.org` zone.
- A selected GitHub owner/team for CODEOWNERS and publishing approval.

## 1. Create two buckets

Suggested names:

```text
second-brain-model-candidates
second-brain-model-releases
```

The candidate bucket remains private. Do not attach a custom domain or enable its `r2.dev` development URL.

The release bucket contains only reviewed public objects. R2 does not expose root bucket listing through a public custom domain, but object URLs are public when known. Never upload a candidate, credential, private report, or signing key to this bucket.

## 2. Attach the production custom domain

Attach the selected hostname directly to `second-brain-model-releases` using the R2 custom-domain settings. Disable the release bucket's `r2.dev` development URL; Cloudflare documents that `r2.dev` is rate-limited and intended for development.

Enable Always Use HTTPS for the hostname. Do not place a Worker in front of model downloads in v1.

## 3. Use immutable release paths

Approved objects use these paths:

```text
/models/sha256/<digest>/model.gguf
/runtimes/sha256/<digest>/<platform-package>
/results/<digest>/result.json
/licenses/<digest>/LICENSE
/licenses/<digest>/NOTICE
```

An existing content-addressed key must never be overwritten. If any bytes change, compute a new digest and publish a new path.

Catalog paths are mutable release pointers and are updated only by the protected publishing workflow:

```text
/catalog/v1/stable.json
/catalog/v1/stable.json.sig
/catalog/v1/beta.json
/catalog/v1/beta.json.sig
/catalog/v1/revoked.json
/catalog/v1/revoked.json.sig
```

Publish in this order:

1. Model artifact.
2. Exact model and runtime license objects, each copied from the adjacent repository `LICENSE` and uploaded at the manifest's `licenses/<sha256>/LICENSE` path.
3. Result record.
4. Catalog JSON.
5. Detached catalog signature last.
6. Public verification of signature, byte size, and SHA-256.

If any verification fails, stop publication and leave the prior signed catalog in service.

## 4. Configure cache behavior

Recommended response metadata:

| Path | Cache-Control |
|---|---|
| `/models/sha256/*` and `/runtimes/sha256/*` | `public, max-age=31536000, immutable` |
| `/results/*` and `/licenses/*` | `public, max-age=31536000, immutable` |
| `/catalog/v1/*` | `no-cache` |

Cloudflare's normal cacheable-file limit is 512 MB on Free, Pro, and Business plans, so most model weights will not be edge-cached. They can still be served from R2, and R2 Internet egress is free under the documented pricing model. Do not add chunk reconstruction to v1 solely to work around the cache limit.

## 5. Configure bucket retention

Optionally apply R2 bucket-lock rules only to the release prefixes `models/sha256/` and `runtimes/sha256/`. A finite retention period such as 180 or 365 days preserves rollback evidence while retaining the option to remove old objects later.

Do not lock the mutable `catalog/` prefix. Test the rule against a disposable object before applying it broadly: a lock prevents overwrite and deletion for its effective retention period.

The owner must choose the v1 retention period before the first release.

## 6. Create least-privilege R2 credentials

Create separate bucket-scoped credentials:

1. Candidate read/write credential, scoped only to `second-brain-model-candidates`.
2. Candidate read-only credential, scoped only to `second-brain-model-candidates`.
3. Release read/write credential, scoped only to `second-brain-model-releases`.

Do not use an account-wide R2 administrator token in GitHub Actions. Rotate long-lived credentials on a documented schedule. R2 also supports short-lived temporary credentials, which may replace the v1 tokens later without changing the consumer contract.

## 7. Configure GitHub environments and secrets

After R2 is enabled, create a `model-candidate` environment for automatic candidate checks with:

```text
R2_ACCOUNT_ID
R2_CANDIDATE_ACCESS_KEY_ID
R2_CANDIDATE_SECRET_ACCESS_KEY
```

Use the protected `model-publish` environment requiring the designated owner with:

```text
R2_ACCOUNT_ID
R2_CANDIDATE_READ_ACCESS_KEY_ID
R2_CANDIDATE_READ_SECRET_ACCESS_KEY
R2_RELEASE_ACCESS_KEY_ID
R2_RELEASE_SECRET_ACCESS_KEY
R2_PUBLIC_BASE_URL
CATALOG_SIGNING_KEY_B64
CATALOG_KEY_ID
```

Set `R2_PUBLIC_BASE_URL` to the exact HTTPS origin without a trailing slash. `CATALOG_SIGNING_KEY_B64` is strict base64 containing either an unencrypted PKCS#8 PEM key or a raw 32-byte Ed25519 seed. Set `CATALOG_KEY_ID` to the fingerprint emitted by the repository key-generation tooling.

Repository Actions permissions should default to read-only. Grant write permissions only to the smallest individual job that must update a pull request or release catalog. Pin third-party Actions to full commit hashes.

## 8. Protect privacy

- Do not enable application telemetry for model installation in this project.
- Do not put device or user identifiers in model URLs, headers, or query strings.
- Do not send prompts, documents, embeddings, local records, or model output to R2.
- Keep private raw check logs in the candidate bucket only when necessary and expire them with a lifecycle rule.
- Treat Cloudflare request metadata as operational metadata, not as a source of product analytics.

## 9. Verify before enabling publication

Before the first catalog release, verify:

- The candidate bucket has no public URL or custom domain.
- The release bucket's `r2.dev` URL is disabled.
- The custom domain serves a disposable content-addressed object over HTTPS.
- The candidate read/write credential cannot access the release bucket.
- The candidate read-only credential cannot write to either bucket.
- The release credential cannot access the candidate bucket.
- Catalog paths bypass caching.
- Model paths return immutable cache metadata.
- Every public model, runtime, result, and license object's bytes and size match the signed catalog.

Delete the disposable test object unless it is covered by a bucket-lock rule.
