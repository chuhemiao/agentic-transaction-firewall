use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Component, Path};
use std::sync::OnceLock;

use atf_core::{sort_json_keys, Timestamp};
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::PolicyError;

const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "signature.json";
const HASH_DOMAIN: &[u8] = b"ATF_POLICY_BUNDLE_V1\0";
const ARTIFACT_DOMAIN: &[u8] = b"ATF_POLICY_BUNDLE_ARTIFACT_V1\0";
const SIGNATURE_DOMAIN: &[u8] = b"ATF_POLICY_BUNDLE_SIGNATURE_V1\0";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 8 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_POLICY_FILES: usize = 256;
const MANIFEST_SCHEMA: &str = include_str!("../../../schemas/policy-bundle.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleLoadContext {
    pub organization_id: String,
    pub environment: String,
    pub evaluated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyBundleManifest {
    manifest_version: String,
    bundle_id: String,
    policy_version: String,
    scope: PolicyBundleScope,
    activates_at: Timestamp,
    expires_at: Timestamp,
    cedar_schema: PolicyBundleFile,
    policy_files: Vec<PolicyBundleFile>,
    bundle_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleScope {
    organization_id: String,
    environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleFile {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyBundleArtifactFile {
    path: String,
    bytes: Vec<u8>,
}

/// Exact executable Policy Bundle bytes suitable for immutable persistence.
/// Decoding never trusts the archive: `PolicyBundle::from_artifact` rechecks
/// the manifest, file digests, Bundle hash and Cedar Schema before evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleArtifact {
    manifest_bytes: Vec<u8>,
    cedar_schema: PolicyBundleArtifactFile,
    policy_files: Vec<PolicyBundleArtifactFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleSignatureDocument {
    signature_version: String,
    algorithm: String,
    key_id: String,
    bundle_hash: String,
    signature: String,
}

/// Detached Ed25519 proof over one exact Bundle hash and publisher Key ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBundleSignature {
    key_id: String,
    bundle_hash: String,
    signature: [u8; 64],
}

pub struct PolicyBundle {
    pub(crate) policies: PolicySet,
    pub(crate) schema: Schema,
    manifest: PolicyBundleManifest,
    artifact: PolicyBundleArtifact,
}

impl fmt::Debug for PolicyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyBundle")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("policy_version", &self.manifest.policy_version)
            .field("bundle_hash", &self.manifest.bundle_hash)
            .finish_non_exhaustive()
    }
}

impl PolicyBundle {
    /// Validate a Bundle for immutable installation, including its declared
    /// active window semantics, without requiring it to be active yet.
    pub fn from_dir_for_install(
        dir: &Path,
        organization_id: &str,
        environment: &str,
    ) -> Result<Self, PolicyError> {
        validate_scope_context(organization_id, environment)?;
        validate_bundle_root(dir)?;
        let bytes = read_regular_file(&dir.join(MANIFEST_FILE), MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
        let raw = std::str::from_utf8(&bytes)
            .map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
        validate_manifest_schema(&value)?;
        let manifest: PolicyBundleManifest = serde_json::from_value(value)
            .map_err(|error| PolicyError::Manifest(error.to_string()))?;
        Self::from_dir(
            dir,
            &PolicyBundleLoadContext {
                organization_id: organization_id.into(),
                environment: environment.into(),
                evaluated_at: manifest.activates_at,
            },
        )
    }

    pub fn from_dir(dir: &Path, context: &PolicyBundleLoadContext) -> Result<Self, PolicyError> {
        validate_load_context(context)?;
        validate_bundle_root(dir)?;
        let manifest_path = dir.join(MANIFEST_FILE);
        let manifest_bytes = read_regular_file(&manifest_path, MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
        let manifest = parse_manifest(&manifest_bytes, context)?;

        let cedar_schema_bytes = read_bound_file(dir, &manifest.cedar_schema)?;
        let mut policy_files = Vec::with_capacity(manifest.policy_files.len());
        let mut total_bytes =
            u64::try_from(cedar_schema_bytes.len()).map_err(|_| PolicyError::BundleTooLarge {
                max_bytes: MAX_BUNDLE_BYTES,
            })?;
        for file in &manifest.policy_files {
            let bytes = read_bound_file(dir, file)?;
            total_bytes = total_bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    PolicyError::BundleTooLarge {
                        max_bytes: MAX_BUNDLE_BYTES,
                    }
                })?)
                .ok_or(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                })?;
            if total_bytes > MAX_BUNDLE_BYTES {
                return Err(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                });
            }
            policy_files.push(PolicyBundleArtifactFile {
                path: file.path.clone(),
                bytes,
            });
        }
        reject_unlisted_policy_files(dir, &manifest.policy_files)?;

        Self::from_artifact(
            PolicyBundleArtifact {
                manifest_bytes,
                cedar_schema: PolicyBundleArtifactFile {
                    path: manifest.cedar_schema.path,
                    bytes: cedar_schema_bytes,
                },
                policy_files,
            },
            context,
        )
    }

    pub fn from_artifact(
        artifact: PolicyBundleArtifact,
        context: &PolicyBundleLoadContext,
    ) -> Result<Self, PolicyError> {
        validate_load_context(context)?;
        if u64::try_from(artifact.manifest_bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
            return Err(PolicyError::FileTooLarge {
                path: MANIFEST_FILE.into(),
                max_bytes: MAX_MANIFEST_BYTES,
            });
        }
        let manifest = parse_manifest(&artifact.manifest_bytes, context)?;
        if artifact.cedar_schema.path != manifest.cedar_schema.path
            || artifact.policy_files.len() != manifest.policy_files.len()
            || artifact
                .policy_files
                .iter()
                .zip(&manifest.policy_files)
                .any(|(archived, declared)| archived.path != declared.path)
        {
            return Err(PolicyError::Artifact(
                "archive file index does not match the manifest".into(),
            ));
        }

        validate_artifact_file(&artifact.cedar_schema, &manifest.cedar_schema)?;
        let mut total_bytes = u64::try_from(artifact.cedar_schema.bytes.len()).map_err(|_| {
            PolicyError::BundleTooLarge {
                max_bytes: MAX_BUNDLE_BYTES,
            }
        })?;
        for (archived, declared) in artifact.policy_files.iter().zip(&manifest.policy_files) {
            validate_artifact_file(archived, declared)?;
            total_bytes = total_bytes
                .checked_add(u64::try_from(archived.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                })?;
            if total_bytes > MAX_BUNDLE_BYTES {
                return Err(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                });
            }
        }

        let calculated_hash = calculate_bundle_hash(
            &manifest,
            &artifact.cedar_schema.bytes,
            artifact
                .policy_files
                .iter()
                .map(|file| (file.path.as_str(), file.bytes.as_slice())),
        );
        if calculated_hash != manifest.bundle_hash {
            return Err(PolicyError::BundleHashMismatch {
                expected: manifest.bundle_hash,
                actual: calculated_hash,
            });
        }

        let schema = Schema::from_json_str(
            std::str::from_utf8(&artifact.cedar_schema.bytes)
                .map_err(|error| PolicyError::CedarSchema(error.to_string()))?,
        )
        .map_err(|error| PolicyError::CedarSchema(error.to_string()))?;
        let combined = artifact
            .policy_files
            .iter()
            .map(|file| std::str::from_utf8(&file.bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PolicyError::Parse(error.to_string()))?
            .join("\n");
        let policies = combined
            .parse::<PolicySet>()
            .map_err(|error| PolicyError::Parse(error.to_string()))?;
        validate_policies(&schema, &policies)?;

        Ok(Self {
            policies,
            schema,
            manifest,
            artifact,
        })
    }

    pub fn bundle_id(&self) -> &str {
        &self.manifest.bundle_id
    }

    pub fn policy_version(&self) -> &str {
        &self.manifest.policy_version
    }

    pub fn bundle_hash(&self) -> &str {
        &self.manifest.bundle_hash
    }

    pub fn organization_id(&self) -> &str {
        &self.manifest.scope.organization_id
    }

    pub fn environment(&self) -> &str {
        &self.manifest.scope.environment
    }

    pub fn activates_at(&self) -> Timestamp {
        self.manifest.activates_at
    }

    pub fn expires_at(&self) -> Timestamp {
        self.manifest.expires_at
    }

    pub fn artifact(&self) -> &PolicyBundleArtifact {
        &self.artifact
    }

    pub(crate) fn validate_evaluation_scope(
        &self,
        organization_id: &str,
        evaluated_at: Timestamp,
    ) -> Result<(), PolicyError> {
        if organization_id != self.manifest.scope.organization_id {
            return Err(PolicyError::ScopeMismatch {
                expected_organization_id: self.manifest.scope.organization_id.clone(),
                expected_environment: self.manifest.scope.environment.clone(),
            });
        }
        validate_active_window(&self.manifest, evaluated_at)
    }
}

impl PolicyBundleArtifact {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(ARTIFACT_DOMAIN);
        append_frame(&mut output, &self.manifest_bytes);
        append_named_frame(
            &mut output,
            &self.cedar_schema.path,
            &self.cedar_schema.bytes,
        );
        let count = u32::try_from(self.policy_files.len())
            .expect("validated Policy Bundle has at most 256 files");
        output.extend_from_slice(&count.to_be_bytes());
        for file in &self.policy_files {
            append_named_frame(&mut output, &file.path, &file.bytes);
        }
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        if !bytes.starts_with(ARTIFACT_DOMAIN) {
            return Err(PolicyError::Artifact("archive domain is invalid".into()));
        }
        let mut cursor = ArtifactCursor::new(&bytes[ARTIFACT_DOMAIN.len()..]);
        let manifest_bytes = cursor.frame(MAX_MANIFEST_BYTES, MANIFEST_FILE)?;
        let cedar_schema = cursor.named_file(MAX_BUNDLE_FILE_BYTES)?;
        let count = usize::try_from(cursor.u32()?)
            .map_err(|_| PolicyError::Artifact("file count is invalid".into()))?;
        if count == 0 || count > MAX_POLICY_FILES {
            return Err(PolicyError::Artifact("file count is outside 1..256".into()));
        }
        let mut policy_files = Vec::with_capacity(count);
        let mut total_bytes = u64::try_from(cedar_schema.bytes.len()).unwrap_or(u64::MAX);
        for _ in 0..count {
            let file = cursor.named_file(MAX_BUNDLE_FILE_BYTES)?;
            total_bytes = total_bytes
                .checked_add(u64::try_from(file.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                })?;
            if total_bytes > MAX_BUNDLE_BYTES {
                return Err(PolicyError::BundleTooLarge {
                    max_bytes: MAX_BUNDLE_BYTES,
                });
            }
            policy_files.push(file);
        }
        if !cursor.is_empty() {
            return Err(PolicyError::Artifact("archive has trailing bytes".into()));
        }
        Ok(Self {
            manifest_bytes,
            cedar_schema,
            policy_files,
        })
    }
}

impl PolicyBundleSignature {
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let bytes = read_regular_file(path, SIGNATURE_FILE, MAX_SIGNATURE_BYTES)?;
        let raw = std::str::from_utf8(&bytes)
            .map_err(|error| PolicyError::SignatureProof(error.to_string()))?;
        Self::from_json(raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, PolicyError> {
        let document: PolicyBundleSignatureDocument = serde_json::from_str(raw)
            .map_err(|error| PolicyError::SignatureProof(error.to_string()))?;
        if document.signature_version != "1" || document.algorithm != "Ed25519" {
            return Err(PolicyError::SignatureProof(
                "unsupported signature version or algorithm".into(),
            ));
        }
        let signature = decode_lower_hex::<64>(&document.signature, "signature")?;
        Self::from_parts(document.key_id, document.bundle_hash, signature)
    }

    pub fn from_parts(
        key_id: String,
        bundle_hash: String,
        signature: [u8; 64],
    ) -> Result<Self, PolicyError> {
        validate_signature_identifier(&key_id)?;
        validate_sha256_hex(&bundle_hash)?;
        Ok(Self {
            key_id,
            bundle_hash,
            signature,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn bundle_hash(&self) -> &str {
        &self.bundle_hash
    }

    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn verify(&self, bundle: &PolicyBundle, public_key: &[u8; 32]) -> Result<(), PolicyError> {
        if self.bundle_hash != bundle.bundle_hash() {
            return Err(PolicyError::SignatureBundleMismatch);
        }
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| PolicyError::SignatureVerification)?;
        let message = policy_bundle_signature_message(&self.key_id, &self.bundle_hash)?;
        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| PolicyError::SignatureVerification)
    }
}

pub fn policy_bundle_signature_message(
    key_id: &str,
    bundle_hash: &str,
) -> Result<Vec<u8>, PolicyError> {
    validate_signature_identifier(key_id)?;
    validate_sha256_hex(bundle_hash)?;
    let mut message = Vec::new();
    message.extend_from_slice(SIGNATURE_DOMAIN);
    append_frame(&mut message, key_id.as_bytes());
    append_frame(&mut message, bundle_hash.as_bytes());
    Ok(message)
}

fn manifest_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema = serde_json::from_str(MANIFEST_SCHEMA)
            .expect("the embedded Policy Bundle manifest Schema is valid JSON");
        jsonschema::validator_for(&schema)
            .expect("the embedded Policy Bundle manifest Schema is valid")
    })
}

fn parse_manifest(
    bytes: &[u8],
    context: &PolicyBundleLoadContext,
) -> Result<PolicyBundleManifest, PolicyError> {
    let raw =
        std::str::from_utf8(bytes).map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
    validate_manifest_schema(&value)?;
    let manifest: PolicyBundleManifest =
        serde_json::from_value(value).map_err(|error| PolicyError::Manifest(error.to_string()))?;
    validate_manifest_semantics(&manifest, context)?;
    Ok(manifest)
}

fn validate_manifest_schema(value: &serde_json::Value) -> Result<(), PolicyError> {
    let errors = manifest_validator()
        .iter_errors(value)
        .map(|error| format!("{} (at {})", error, error.instance_path))
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::ManifestSchema(errors.join("; ")))
    }
}

fn validate_load_context(context: &PolicyBundleLoadContext) -> Result<(), PolicyError> {
    validate_scope_context(&context.organization_id, &context.environment)
}

fn validate_scope_context(organization_id: &str, environment: &str) -> Result<(), PolicyError> {
    if organization_id.trim().is_empty() || environment.trim().is_empty() {
        return Err(PolicyError::InvalidLoadContext);
    }
    Ok(())
}

fn validate_manifest_semantics(
    manifest: &PolicyBundleManifest,
    context: &PolicyBundleLoadContext,
) -> Result<(), PolicyError> {
    if manifest.scope.organization_id != context.organization_id
        || manifest.scope.environment != context.environment
    {
        return Err(PolicyError::ScopeMismatch {
            expected_organization_id: manifest.scope.organization_id.clone(),
            expected_environment: manifest.scope.environment.clone(),
        });
    }
    if manifest.activates_at >= manifest.expires_at {
        return Err(PolicyError::Manifest(
            "activates_at must be earlier than expires_at".into(),
        ));
    }
    if !is_millisecond_aligned(manifest.activates_at)
        || !is_millisecond_aligned(manifest.expires_at)
    {
        return Err(PolicyError::Manifest(
            "activates_at and expires_at must align to whole milliseconds".into(),
        ));
    }
    validate_active_window(manifest, context.evaluated_at)?;

    let mut paths = HashSet::new();
    validate_relative_file_path(&manifest.cedar_schema.path)?;
    validate_extension(&manifest.cedar_schema.path, "json")?;
    paths.insert(manifest.cedar_schema.path.as_str());

    let mut previous = None;
    for file in &manifest.policy_files {
        validate_relative_file_path(&file.path)?;
        validate_extension(&file.path, "cedar")?;
        if !paths.insert(file.path.as_str()) {
            return Err(PolicyError::DuplicateFile(file.path.clone()));
        }
        if let Some(previous) = previous {
            if file.path.as_str() <= previous {
                return Err(PolicyError::FilesNotSorted);
            }
        }
        previous = Some(file.path.as_str());
    }
    Ok(())
}

fn validate_extension(path: &str, expected: &str) -> Result<(), PolicyError> {
    if Path::new(path)
        .extension()
        .is_none_or(|extension| extension != expected)
    {
        return Err(PolicyError::InvalidFilePath(path.to_owned()));
    }
    Ok(())
}

fn is_millisecond_aligned(timestamp: Timestamp) -> bool {
    timestamp.as_datetime().timestamp_subsec_nanos() % 1_000_000 == 0
}

fn validate_active_window(
    manifest: &PolicyBundleManifest,
    evaluated_at: Timestamp,
) -> Result<(), PolicyError> {
    if evaluated_at < manifest.activates_at || evaluated_at >= manifest.expires_at {
        return Err(PolicyError::Inactive {
            activates_at: manifest.activates_at,
            expires_at: manifest.expires_at,
            evaluated_at,
        });
    }
    Ok(())
}

fn validate_relative_file_path(path: &str) -> Result<(), PolicyError> {
    let parsed = Path::new(path);
    let mut components = parsed.components();
    if path.is_empty()
        || parsed.is_absolute()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(PolicyError::InvalidFilePath(path.to_owned()));
    }
    Ok(())
}

fn read_bound_file(dir: &Path, file: &PolicyBundleFile) -> Result<Vec<u8>, PolicyError> {
    let path = dir.join(&file.path);
    let bytes = read_regular_file(&path, &file.path, MAX_BUNDLE_FILE_BYTES)?;
    let actual = atf_core::sha256_hex(&bytes);
    if actual != file.sha256 {
        return Err(PolicyError::FileDigestMismatch {
            path: file.path.clone(),
            expected: file.sha256.clone(),
            actual,
        });
    }
    Ok(bytes)
}

fn validate_artifact_file(
    archived: &PolicyBundleArtifactFile,
    declared: &PolicyBundleFile,
) -> Result<(), PolicyError> {
    if u64::try_from(archived.bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_FILE_BYTES {
        return Err(PolicyError::FileTooLarge {
            path: archived.path.clone(),
            max_bytes: MAX_BUNDLE_FILE_BYTES,
        });
    }
    let actual = atf_core::sha256_hex(&archived.bytes);
    if actual != declared.sha256 {
        return Err(PolicyError::FileDigestMismatch {
            path: archived.path.clone(),
            expected: declared.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn validate_bundle_root(dir: &Path) -> Result<(), PolicyError> {
    let metadata = fs::symlink_metadata(dir)
        .map_err(|error| PolicyError::Io(format!("{}: {error}", dir.display())))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PolicyError::InvalidFilePath(dir.display().to_string()));
    }
    Ok(())
}

fn read_regular_file(
    path: &Path,
    logical_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, PolicyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| PolicyError::Io(format!("{}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PolicyError::InvalidFilePath(logical_path.to_owned()));
    }
    if metadata.len() > max_bytes {
        return Err(PolicyError::FileTooLarge {
            path: logical_path.to_owned(),
            max_bytes,
        });
    }
    let file = fs::File::open(path)
        .map_err(|error| PolicyError::Io(format!("{}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len().min(max_bytes)).unwrap_or(0));
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PolicyError::Io(format!("{}: {error}", path.display())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(PolicyError::FileTooLarge {
            path: logical_path.to_owned(),
            max_bytes,
        });
    }
    Ok(bytes)
}

fn reject_unlisted_policy_files(
    dir: &Path,
    declared: &[PolicyBundleFile],
) -> Result<(), PolicyError> {
    let declared = declared
        .iter()
        .map(|file| file.path.as_str())
        .collect::<HashSet<_>>();
    for entry in
        fs::read_dir(dir).map_err(|error| PolicyError::Io(format!("{}: {error}", dir.display())))?
    {
        let entry = entry.map_err(|error| PolicyError::Io(error.to_string()))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "cedar")
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| PolicyError::InvalidFilePath(path.display().to_string()))?;
            if !declared.contains(name) {
                return Err(PolicyError::UnlistedPolicyFile(name.to_owned()));
            }
        }
    }
    Ok(())
}

fn calculate_bundle_hash<'a>(
    manifest: &PolicyBundleManifest,
    cedar_schema_bytes: &[u8],
    policy_bytes: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let mut unsigned =
        serde_json::to_value(manifest).expect("a Policy Bundle manifest always serializes to JSON");
    unsigned
        .as_object_mut()
        .expect("a Policy Bundle manifest is an object")
        .remove("bundle_hash");
    let canonical_manifest = serde_json::to_vec(&sort_json_keys(unsigned))
        .expect("a canonical Policy Bundle manifest always serializes");

    let mut input = Vec::new();
    input.extend_from_slice(HASH_DOMAIN);
    append_frame(&mut input, &canonical_manifest);
    append_named_frame(&mut input, &manifest.cedar_schema.path, cedar_schema_bytes);
    for (path, bytes) in policy_bytes {
        append_named_frame(&mut input, path, bytes);
    }
    atf_core::sha256_hex(&input)
}

fn append_named_frame(input: &mut Vec<u8>, path: &str, bytes: &[u8]) {
    append_frame(input, path.as_bytes());
    append_frame(input, bytes);
}

fn append_frame(input: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("bundle files fit in a u64 length frame");
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(bytes);
}

struct ArtifactCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ArtifactCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn u32(&mut self) -> Result<u32, PolicyError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes
                .try_into()
                .expect("ArtifactCursor returned exactly four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, PolicyError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes
                .try_into()
                .expect("ArtifactCursor returned exactly eight bytes"),
        ))
    }

    fn frame(&mut self, max_bytes: u64, label: &str) -> Result<Vec<u8>, PolicyError> {
        let length = self.u64()?;
        if length > max_bytes {
            return Err(PolicyError::FileTooLarge {
                path: label.into(),
                max_bytes,
            });
        }
        let length = usize::try_from(length)
            .map_err(|_| PolicyError::Artifact("frame length is invalid".into()))?;
        Ok(self.take(length)?.to_vec())
    }

    fn named_file(&mut self, max_bytes: u64) -> Result<PolicyBundleArtifactFile, PolicyError> {
        let path = self.frame(255, "archive path")?;
        let path = String::from_utf8(path)
            .map_err(|error| PolicyError::Artifact(format!("archive path: {error}")))?;
        let bytes = self.frame(max_bytes, &path)?;
        Ok(PolicyBundleArtifactFile { path, bytes })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PolicyError> {
        if length > self.remaining.len() {
            return Err(PolicyError::Artifact("archive is truncated".into()));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
}

fn validate_signature_identifier(value: &str) -> Result<(), PolicyError> {
    let mut bytes = value.bytes();
    if value.len() > 128
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(PolicyError::SignatureProof(
            "key_id is not a canonical identifier".into(),
        ));
    }
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<(), PolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::SignatureProof(
            "bundle_hash is not lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

fn decode_lower_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], PolicyError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::SignatureProof(format!(
            "{label} must be canonical lowercase hexadecimal"
        )));
    }
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| PolicyError::SignatureProof(error.to_string()))?;
    }
    Ok(decoded)
}

fn validate_policies(schema: &Schema, policies: &PolicySet) -> Result<(), PolicyError> {
    // Cedar intentionally keeps policy validation separate from authorization;
    // bundles must pass strict validation before they can reach evaluate.
    // Source: https://docs.cedarpolicy.com/policies/validation.html
    let result = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    let diagnostics = result
        .validation_errors()
        .map(ToString::to_string)
        .chain(result.validation_warnings().map(ToString::to_string))
        .collect::<Vec<_>>();
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::CedarValidation(diagnostics.join("; ")))
    }
}
