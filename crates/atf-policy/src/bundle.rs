use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Component, Path};
use std::sync::OnceLock;

use atf_core::{sort_json_keys, Timestamp};
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use serde::{Deserialize, Serialize};

use crate::PolicyError;

const MANIFEST_FILE: &str = "manifest.json";
const HASH_DOMAIN: &[u8] = b"ATF_POLICY_BUNDLE_V1\0";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
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

pub struct PolicyBundle {
    pub(crate) policies: PolicySet,
    pub(crate) schema: Schema,
    manifest: PolicyBundleManifest,
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
    pub fn from_dir(dir: &Path, context: &PolicyBundleLoadContext) -> Result<Self, PolicyError> {
        validate_load_context(context)?;
        validate_bundle_root(dir)?;
        let manifest_path = dir.join(MANIFEST_FILE);
        let raw = read_regular_file(&manifest_path, MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
        let raw = std::str::from_utf8(&raw)
            .map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|error| PolicyError::ManifestJson(error.to_string()))?;
        validate_manifest_schema(&value)?;
        let manifest: PolicyBundleManifest = serde_json::from_value(value)
            .map_err(|error| PolicyError::Manifest(error.to_string()))?;
        validate_manifest_semantics(&manifest, context)?;

        let cedar_schema_bytes = read_bound_file(dir, &manifest.cedar_schema)?;
        let mut policy_bytes = Vec::with_capacity(manifest.policy_files.len());
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
            policy_bytes.push((file.path.clone(), bytes));
        }
        reject_unlisted_policy_files(dir, &manifest.policy_files)?;

        let calculated_hash = calculate_bundle_hash(
            &manifest,
            &cedar_schema_bytes,
            policy_bytes
                .iter()
                .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
        );
        if calculated_hash != manifest.bundle_hash {
            return Err(PolicyError::BundleHashMismatch {
                expected: manifest.bundle_hash,
                actual: calculated_hash,
            });
        }

        let schema = Schema::from_json_str(
            std::str::from_utf8(&cedar_schema_bytes)
                .map_err(|error| PolicyError::CedarSchema(error.to_string()))?,
        )
        .map_err(|error| PolicyError::CedarSchema(error.to_string()))?;
        let combined = policy_bytes
            .iter()
            .map(|(_, bytes)| std::str::from_utf8(bytes))
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

fn manifest_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema = serde_json::from_str(MANIFEST_SCHEMA)
            .expect("the embedded Policy Bundle manifest Schema is valid JSON");
        jsonschema::validator_for(&schema)
            .expect("the embedded Policy Bundle manifest Schema is valid")
    })
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
    if context.organization_id.trim().is_empty() || context.environment.trim().is_empty() {
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
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len().min(max_bytes)).unwrap_or(usize::MAX));
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

fn validate_policies(schema: &Schema, policies: &PolicySet) -> Result<(), PolicyError> {
    // Cedar intentionally keeps policy validation separate from authorization;
    // bundles must pass strict validation before they can reach evaluate_at.
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
