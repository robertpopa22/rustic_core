pub mod mapper;
pub use mapper::LocalSourceSaveOptions;

use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use bytesize::ByteSize;
use derive_setters::Setters;
use ignore::{Walk, WalkBuilder};
use log::warn;
use serde_with::{DisplayFromStr, serde_as};

#[cfg(not(windows))]
use std::num::TryFromIntError;

use crate::{
    Excludes,
    backend::{ReadSource, ReadSourceEntry, ReadSourceOpen},
    error::{ErrorKind, RusticError, RusticResult},
};

/// [`IgnoreErrorKind`] describes the errors that can be returned by a Ignore action in Backends
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum IgnoreErrorKind {
    #[cfg(all(not(windows), not(target_os = "openbsd")))]
    /// Error getting xattrs for `{path:?}`: `{source:?}`
    ErrorXattr {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Error reading link target for `{path:?}`: `{source:?}`
    ErrorLink {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(not(windows))]
    /// Error converting ctime `{ctime}` and `ctime_nsec` `{ctime_nsec}` to Utc Timestamp: `{source:?}`
    CtimeConversionToTimestampFailed {
        ctime: i64,
        ctime_nsec: i64,
        source: TryFromIntError,
    },
    /// Error acquiring metadata for `{name}`: `{source:?}`
    AcquiringMetadataFailed { name: String, source: ignore::Error },
    /// time error
    JiffError(#[from] jiff::Error),
}

pub(crate) type IgnoreResult<T> = Result<T, IgnoreErrorKind>;

/// A [`LocalSource`] is a source from local paths which is used to be read from (i.e. to backup it).
#[derive(Debug)]
pub struct LocalSource {
    /// The walk builder.
    builder: WalkBuilder,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
}

#[serde_as]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "merge", derive(conflate::Merge))]
#[derive(serde::Deserialize, serde::Serialize, Default, Clone, Debug, Setters)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
#[setters(into)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)]
/// [`LocalSourceFilterOptions`] allow to filter a local source by various criteria.
pub struct LocalSourceFilterOptions {
    /// Ignore files based on .gitignore files
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub git_ignore: bool,

    /// Do not require a git repository to apply git-ignore rule
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub no_require_git: bool,

    /// Treat the provided filename like a .gitignore file (can be specified multiple times)
    #[cfg_attr(
        feature = "clap",
        clap(long = "custom-ignorefile", value_name = "FILE")
    )]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub custom_ignorefiles: Vec<String>,

    /// Exclude contents of directories containing this filename (can be specified multiple times).
    ///
    /// Use `FILE:HEADER` to only exclude if the file starts with the given header.
    /// As in restic, the directory itself and the tag file are kept.
    #[cfg_attr(feature = "clap", clap(long, value_name = "FILE[:HEADER]"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_present: Vec<String>,

    /// Exclude contents of cache directories marked by a valid `CACHEDIR.TAG` file
    /// (see <https://bford.info/cachedir/>). Same as
    /// `--exclude-if-present "CACHEDIR.TAG:Signature: 8a477f597d28d172789f06886806bc55"`.
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub exclude_caches: bool,

    /// Exclude files/directories having the given extended attribute set (can be specified multiple times)
    #[cfg_attr(feature = "clap", clap(long, value_name = "XATTR"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_xattr: Vec<String>,

    /// Exclude other file systems, don't cross filesystem boundaries and subvolumes
    #[cfg_attr(feature = "clap", clap(long, short = 'x'))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub one_file_system: bool,

    /// Maximum size of files to be backed up. Larger files will be excluded.
    #[cfg_attr(feature = "clap", clap(long, value_name = "SIZE"))]
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub exclude_larger_than: Option<ByteSize>,
}

/// A tag file given by `--exclude-if-present` or `--exclude-caches`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExcludeTag {
    /// Name of the tag file
    filename: OsString,
    /// Header the tag file must start with (if any)
    header: Option<Vec<u8>>,
}

impl ExcludeTag {
    /// Signature of a valid `CACHEDIR.TAG`, see <https://bford.info/cachedir/>
    const CACHEDIR_HEADER: &'static str = "Signature: 8a477f597d28d172789f06886806bc55";

    /// Parse `FILE[:HEADER]`, as restic does: split at the first `:`.
    fn parse(s: &str) -> Self {
        match s.split_once(':') {
            Some((file, header)) if !header.is_empty() => Self {
                filename: OsString::from(file),
                header: Some(header.as_bytes().to_vec()),
            },
            Some((file, _)) => Self {
                filename: OsString::from(file),
                header: None,
            },
            None => Self {
                filename: OsString::from(s),
                header: None,
            },
        }
    }

    fn cachedir() -> Self {
        Self::parse(&format!("CACHEDIR.TAG:{}", Self::CACHEDIR_HEADER))
    }

    /// Returns true if `dir` contains this tag file (with matching header, if one is given).
    fn is_present_in(&self, dir: &Path) -> bool {
        let path = dir.join(&self.filename);
        let Some(header) = &self.header else {
            return path.exists();
        };
        let mut buf = vec![0; header.len()];
        match File::open(&path).and_then(|mut f| f.read_exact(&mut buf)) {
            Ok(()) if &buf == header => true,
            Ok(()) => {
                warn!(
                    "tag file {} does not start with the expected header, not excluding",
                    path.display()
                );
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                warn!(
                    "could not read header of tag file {}, not excluding: {err}",
                    path.display()
                );
                false
            }
        }
    }
}

impl LocalSource {
    /// Create a local source from [`LocalSourceSaveOptions`], [`LocalSourceFilterOptions`] and backup path(s).
    ///
    /// # Arguments
    ///
    /// * `save_opts` - The [`LocalSourceSaveOptions`] to use.
    /// * `filter_opts` - The [`LocalSourceFilterOptions`] to use.
    /// * `backup_paths` - The backup path(s) to use.
    ///
    /// # Returns
    ///
    /// The created local source.
    ///
    /// # Errors
    ///
    /// * If the a glob pattern could not be added to the override builder.
    /// * If a glob file could not be read.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        save_opts: LocalSourceSaveOptions,
        excludes: &Excludes,
        filter_opts: &LocalSourceFilterOptions,
        backup_paths: &[impl AsRef<Path>],
    ) -> RusticResult<Self> {
        let mut walk_builder = WalkBuilder::new(&backup_paths[0]);

        for path in &backup_paths[1..] {
            _ = walk_builder.add(path);
        }

        let overrides = excludes.as_override()?;

        for file in &filter_opts.custom_ignorefiles {
            _ = walk_builder.add_custom_ignore_filename(file);
        }

        _ = walk_builder
            .follow_links(false)
            .hidden(false)
            .ignore(false)
            .git_ignore(filter_opts.git_ignore)
            .git_exclude(filter_opts.git_ignore)
            .require_git(!filter_opts.no_require_git)
            .sort_by_file_path(Path::cmp)
            .same_file_system(filter_opts.one_file_system)
            .max_filesize(filter_opts.exclude_larger_than.map(|s| s.as_u64()))
            .overrides(overrides);

        let mut exclude_if_present: Vec<ExcludeTag> = filter_opts
            .exclude_if_present
            .iter()
            .map(|s| ExcludeTag::parse(s))
            .collect();
        if filter_opts.exclude_caches {
            exclude_if_present.push(ExcludeTag::cachedir());
        }
        let exclude_if_xattr: Vec<OsString> = filter_opts
            .exclude_if_xattr
            .iter()
            .map(OsString::from)
            .collect();

        if !exclude_if_xattr.is_empty() {
            #[cfg(any(windows, target_os = "openbsd"))]
            warn!("exclude-if-xattr is not supported on this platform");
            #[cfg(not(any(windows, target_os = "openbsd")))]
            if !xattr::SUPPORTED_PLATFORM {
                warn!("exclude-if-xattr is not supported on this platform");
            }
        }

        let needs_entry_filter = !exclude_if_present.is_empty() || !exclude_if_xattr.is_empty();

        if needs_entry_filter {
            _ = walk_builder.filter_entry(move |entry| {
                // exclude-if-present: skip the contents of directories containing a tag file,
                // but keep the directory itself and the tag file (same as restic)
                if !exclude_if_present.is_empty()
                    && entry.depth() > 0
                    && let Some(parent) = entry.path().parent()
                    && exclude_if_present.iter().any(|tag| {
                        entry.file_name() != tag.filename.as_os_str() && tag.is_present_in(parent)
                    })
                {
                    return false;
                }

                // exclude-if-xattr: skip entries that have a matching xattr
                #[cfg(not(any(windows, target_os = "openbsd")))]
                if xattr::SUPPORTED_PLATFORM && !exclude_if_xattr.is_empty() {
                    match xattr::list(entry.path()) {
                        Ok(mut attrs) => {
                            if attrs.any(|attr| exclude_if_xattr.contains(&attr)) {
                                return false;
                            }
                        }
                        Err(err) => {
                            warn!(
                                "Error reading xattrs for {}, not excluding: {err}",
                                entry.path().display()
                            );
                        }
                    }
                }

                true
            });
        }

        let builder = walk_builder;

        Ok(Self { builder, save_opts })
    }
}

#[derive(Debug)]
/// Describes an open file from the local backend.
pub struct OpenFile(PathBuf);

impl ReadSourceOpen for OpenFile {
    type Reader = File;

    /// Open the file from the local backend.
    ///
    /// # Returns
    ///
    /// The read handle to the file from the local backend.
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    fn open(self) -> RusticResult<Self::Reader> {
        let path = self.0;
        File::open(&path).map_err(|err| {
            RusticError::with_source(
                ErrorKind::InputOutput,
                "Failed to open file at `{path}`. Please make sure the file exists and is accessible.",
                err,
            )
            .attach_context("path", path.display().to_string())
        })
    }
}

impl ReadSource for LocalSource {
    type Open = OpenFile;
    type Iter = LocalSourceWalker;

    /// Get the size of the local source.
    ///
    /// # Returns
    ///
    /// The size of the local source or `None` if the size could not be determined.
    ///
    /// # Errors
    ///
    /// * If the size could not be determined.
    fn size(&self) -> RusticResult<Option<u64>> {
        let mut size = 0;
        for entry in self.builder.build() {
            if let Err(err) = entry.and_then(|e| e.metadata()).map(|m| {
                size += if m.is_dir() { 0 } else { m.len() };
            }) {
                warn!("ignoring error {err}");
            }
        }
        Ok(Some(size))
    }

    /// Iterate over the entries of the local source.
    ///
    /// # Returns
    ///
    /// An iterator over the entries of the local source.
    fn entries(&self) -> Self::Iter {
        LocalSourceWalker {
            walker: self.builder.build(),
            save_opts: self.save_opts,
        }
    }
}

fn ignore_error_path(err: &ignore::Error) -> Option<String> {
    match err {
        ignore::Error::WithPath { path, .. } => Some(path.display().to_string()),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            ignore_error_path(err)
        }
        ignore::Error::Loop { child, .. } => Some(child.display().to_string()),
        _ => None,
    }
}

// Walk doesn't implement Debug
#[allow(missing_debug_implementations)]
pub struct LocalSourceWalker {
    /// The walk iterator.
    walker: Walk,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
}

impl Iterator for LocalSourceWalker {
    type Item = RusticResult<ReadSourceEntry<OpenFile>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.walker.next() {
            // ignore root dir, i.e. an entry with depth 0 of type dir
            Some(Ok(entry)) if entry.depth() == 0 && entry.file_type().unwrap().is_dir() => {
                self.walker.next()
            }
            item => item,
        }
        .map(|e| {
            let entry = e.map_err(|err| {
                let path = ignore_error_path(&err);
                let rustic_err = if path.is_some() {
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "Failed to read source path `{path}`.",
                        err,
                    )
                } else {
                    RusticError::with_source(
                        ErrorKind::InputOutput,
                        "Failed to read source path.",
                        err,
                    )
                };
                match path {
                    Some(path) => rustic_err.attach_context("path", path),
                    None => rustic_err,
                }
            })?;
            let path = entry.path().display().to_string();
            self.save_opts.map_entry(entry).map_err(|err| {
                RusticError::with_source(
                    ErrorKind::InputOutput,
                    "Failed to map directory entry `{path}` to a backup source entry.",
                    err,
                )
                .attach_context("path", path)
            })
        })
    }
}

#[cfg(test)]
mod exclude_tag_tests {
    use super::*;

    fn names(src: &LocalSource) -> Vec<String> {
        let root = src.builder.build().next().unwrap().unwrap().into_path();
        let mut v: Vec<String> = src
            .builder
            .build()
            .filter_map(Result::ok)
            .filter(|e| e.depth() > 0)
            .map(|e| {
                e.path()
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        v.sort();
        v
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for d in ["cache", "badcache", "marked", "plain"] {
            std::fs::create_dir(p.join(d)).unwrap();
            std::fs::write(p.join(d).join("data"), b"x").unwrap();
        }
        std::fs::write(
            p.join("cache/CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n# comment",
        )
        .unwrap();
        std::fs::write(p.join("badcache/CACHEDIR.TAG"), b"nope").unwrap();
        std::fs::write(p.join("marked/.nobackup"), b"").unwrap();
        dir
    }

    fn source(dir: &Path, opts: &LocalSourceFilterOptions) -> LocalSource {
        LocalSource::new(
            LocalSourceSaveOptions::default(),
            &Excludes::default(),
            opts,
            &[dir],
        )
        .unwrap()
    }

    #[test]
    fn parse_file_and_header() {
        assert_eq!(
            ExcludeTag::parse("a.tag"),
            ExcludeTag {
                filename: "a.tag".into(),
                header: None
            }
        );
        assert_eq!(
            ExcludeTag::parse("a.tag:Sig: x"),
            ExcludeTag {
                filename: "a.tag".into(),
                header: Some(b"Sig: x".to_vec())
            }
        );
    }

    #[test]
    fn exclude_caches_keeps_dir_and_tag_like_restic() {
        let dir = tree();
        let opts = LocalSourceFilterOptions {
            exclude_caches: true,
            ..Default::default()
        };
        assert_eq!(
            names(&source(dir.path(), &opts)),
            [
                "badcache",
                "badcache/CACHEDIR.TAG",
                "badcache/data",
                "cache",
                "cache/CACHEDIR.TAG",
                "marked",
                "marked/.nobackup",
                "marked/data",
                "plain",
                "plain/data",
            ]
        );
    }

    #[test]
    fn exclude_if_present_keeps_dir_and_tag_like_restic() {
        let dir = tree();
        let opts = LocalSourceFilterOptions {
            exclude_if_present: vec![".nobackup".into()],
            ..Default::default()
        };
        let got = names(&source(dir.path(), &opts));
        assert!(got.contains(&"marked".to_string()));
        assert!(got.contains(&"marked/.nobackup".to_string()));
        assert!(!got.contains(&"marked/data".to_string()));
        assert!(got.contains(&"cache/data".to_string()));
    }
}
