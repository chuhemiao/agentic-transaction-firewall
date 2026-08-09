use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

const MAX_SOCKET_PATH_BYTES: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricsServerConfig {
    socket_path: PathBuf,
}

impl MetricsServerConfig {
    pub fn new(socket_path: PathBuf) -> Result<Self, MetricsServerConfigError> {
        if !socket_path.is_absolute()
            || socket_path
                .parent()
                .is_none_or(|parent| parent == Path::new("/"))
            || socket_path.file_name().is_none()
            || socket_path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(MetricsServerConfigError("socket path"));
        }
        #[cfg(unix)]
        if socket_path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
            return Err(MetricsServerConfigError("socket path length"));
        }
        Ok(Self { socket_path })
    }

    pub fn from_env() -> Result<Self, MetricsServerConfigError> {
        let socket_path = std::env::var_os("ATF_METRICS_SOCKET_PATH")
            .ok_or(MetricsServerConfigError("ATF_METRICS_SOCKET_PATH"))?;
        Self::new(PathBuf::from(socket_path))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(unix)]
    pub async fn bind(&self) -> io::Result<tokio::net::UnixListener> {
        self.validate_parent_directory()?;
        match std::fs::symlink_metadata(&self.socket_path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                match tokio::net::UnixStream::connect(&self.socket_path).await {
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "Metrics socket already has a live listener",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(&self.socket_path)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Metrics socket path is occupied by a non-socket object",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = tokio::net::UnixListener::bind(&self.socket_path)?;
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;
        Ok(listener)
    }

    #[cfg(unix)]
    fn validate_parent_directory(&self) -> io::Result<()> {
        let parent = self
            .socket_path
            .parent()
            .expect("validated Metrics socket paths have a parent");
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Metrics socket parent must be a real directory",
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o700 != 0o700 || mode & 0o010 == 0 || mode & 0o027 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Metrics socket parent permissions must be owner-rwx, group-traverse, and not writable by group or accessible by others",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsServerConfigError(&'static str);

impl fmt::Display for MetricsServerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Gateway Metrics {} configuration",
            self.0
        )
    }
}

impl std::error::Error for MetricsServerConfigError {}

#[cfg(all(test, unix))]
mod tests {
    use super::MetricsServerConfig;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    #[test]
    fn socket_path_is_absolute_normalized_and_bounded() {
        assert!(MetricsServerConfig::new("metrics.sock".into()).is_err());
        assert!(MetricsServerConfig::new("/metrics.sock".into()).is_err());
        assert!(MetricsServerConfig::new("/run/atf/../metrics.sock".into()).is_err());
        assert!(
            MetricsServerConfig::new(format!("/run/atf/{}.sock", "x".repeat(100)).into()).is_err()
        );
        assert!(MetricsServerConfig::new("/run/atf/metrics.sock".into()).is_ok());
    }

    #[tokio::test]
    async fn bind_requires_a_protected_real_parent_and_replaces_only_a_stale_socket() {
        let root =
            std::path::Path::new("/tmp").join(format!("atf-metrics-{}", atf_core::new_ulid()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o710)).unwrap();
        let path = root.join("metrics.sock");
        let config = MetricsServerConfig::new(path.clone()).unwrap();

        let first = config.bind().await.unwrap();
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o660
        );
        assert_eq!(
            config.bind().await.unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
        drop(first);
        let second = config.bind().await.unwrap();
        drop(second);

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"occupied").unwrap();
        assert!(config.bind().await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"occupied");
        std::fs::remove_file(&path).unwrap();

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(config.bind().await.is_err());
        std::fs::remove_dir(&root).unwrap();
    }
}
