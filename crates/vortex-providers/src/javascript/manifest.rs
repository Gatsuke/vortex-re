//! Tolerant `package.json` parsing.
//!
//! Malformed fields never abort a run: each problem is collected and reported
//! as a warning, and every successfully extracted field stays usable. This is
//! deliberate — real-world artifacts contain manifests that strict parsers
//! reject, and evidence quality depends on keeping the parts we can read.

use serde_json::Value;

/// A declared dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDecl {
    /// Package name.
    pub name: String,
    /// Declared version range (raw string).
    pub range: String,
}

/// A parsed (possibly partial) `package.json`.
#[derive(Debug, Clone, Default)]
pub struct PackageManifest {
    /// Path relative to the inspection root.
    pub rel_path: String,
    /// SHA-256 of the file.
    pub sha256: String,
    /// File size.
    pub size: u64,
    /// `name` field.
    pub name: Option<String>,
    /// `version` field.
    pub version: Option<String>,
    /// `main` field.
    pub main: Option<String>,
    /// `module` field.
    pub module: Option<String>,
    /// `type` field (`commonjs` / `module`).
    pub type_field: Option<String>,
    /// Script names (values are not recorded).
    pub scripts: Vec<String>,
    /// Runtime dependencies.
    pub dependencies: Vec<DependencyDecl>,
    /// Development dependencies.
    pub dev_dependencies: Vec<DependencyDecl>,
    /// Problems found while parsing.
    pub problems: Vec<String>,
    /// Whether `electron` appears in dependencies or devDependencies.
    pub electron: bool,
}

impl PackageManifest {
    /// All dependency names (runtime + dev).
    pub fn all_dependency_names(&self) -> Vec<&str> {
        self.dependencies
            .iter()
            .map(|d| d.name.as_str())
            .chain(self.dev_dependencies.iter().map(|d| d.name.as_str()))
            .collect()
    }

    /// The entry point candidate (`main`, then `module`).
    pub fn entry_point(&self) -> Option<&str> {
        self.main.as_deref().or(self.module.as_deref())
    }
}

/// Parse a `package.json` from bytes.
pub fn parse_manifest(rel_path: &str, bytes: &[u8], sha256: &str) -> PackageManifest {
    let mut manifest = PackageManifest {
        rel_path: rel_path.to_string(),
        sha256: sha256.to_string(),
        size: bytes.len() as u64,
        ..PackageManifest::default()
    };
    let parsed: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(err) => {
            manifest
                .problems
                .push(format!("file is not valid JSON: {err}"));
            return manifest;
        }
    };
    let Some(object) = parsed.as_object() else {
        manifest
            .problems
            .push("top-level JSON value is not an object".to_string());
        return manifest;
    };

    manifest.name = string_field(object, "name", &mut manifest.problems);
    manifest.version = string_field(object, "version", &mut manifest.problems);
    manifest.main = string_field(object, "main", &mut manifest.problems);
    manifest.module = string_field(object, "module", &mut manifest.problems);
    manifest.type_field = string_field(object, "type", &mut manifest.problems);

    if let Some(scripts) = object.get("scripts").and_then(Value::as_object) {
        let mut names: Vec<String> = scripts.keys().cloned().collect();
        names.sort();
        manifest.scripts = names;
    } else if let Some(scripts) = object.get("scripts") {
        if !scripts.is_null() {
            manifest
                .problems
                .push("'scripts' is present but is not an object".to_string());
        }
    }

    manifest.dependencies = dependency_list(object, "dependencies", &mut manifest.problems);
    manifest.dev_dependencies = dependency_list(object, "devDependencies", &mut manifest.problems);

    let electron_dep = |list: &[DependencyDecl]| list.iter().any(|d| d.name == "electron");
    manifest.electron =
        electron_dep(&manifest.dependencies) || electron_dep(&manifest.dev_dependencies);

    manifest
}

fn string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    match object.get(key) {
        None => None,
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(other) => {
            problems.push(format!("'{key}' is present but is not a string"));
            let _ = other;
            None
        }
    }
}

fn dependency_list(
    object: &serde_json::Map<String, Value>,
    key: &str,
    problems: &mut Vec<String>,
) -> Vec<DependencyDecl> {
    match object.get(key) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => {
            let mut list: Vec<DependencyDecl> = map
                .iter()
                .map(|(name, range)| DependencyDecl {
                    name: name.clone(),
                    range: range.as_str().map(str::to_string).unwrap_or_else(|| {
                        problems.push(format!("'{key}.{name}' is not a string"));
                        "<non-string>".to_string()
                    }),
                })
                .collect();
            list.sort_by(|a, b| a.name.cmp(&b.name));
            list
        }
        Some(_) => {
            problems.push(format!("'{key}' is present but is not an object"));
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_manifest() {
        let body = br#"{
            "name": "demo-app",
            "version": "1.2.3",
            "main": "src/main.js",
            "type": "commonjs",
            "scripts": { "start": "electron .", "test": "node src/main.js" },
            "dependencies": { "minimist": "^1.2.8" },
            "devDependencies": { "electron": "^33.0.0" }
        }"#;
        let manifest = parse_manifest("package.json", body, "aa");
        assert_eq!(manifest.name.as_deref(), Some("demo-app"));
        assert_eq!(manifest.version.as_deref(), Some("1.2.3"));
        assert_eq!(manifest.entry_point(), Some("src/main.js"));
        assert_eq!(manifest.scripts, vec!["start", "test"]);
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.dev_dependencies.len(), 1);
        assert!(manifest.electron);
        assert!(manifest.problems.is_empty());
    }

    #[test]
    fn malformed_json_reports_problem_and_continues() {
        let manifest = parse_manifest("bad/package.json", b"{ not json", "bb");
        assert_eq!(manifest.problems.len(), 1);
        assert!(manifest.problems[0].contains("not valid JSON"));
        assert!(manifest.name.is_none());
    }

    #[test]
    fn wrong_field_types_are_reported() {
        let body = br#"{"name": 42, "main": true, "dependencies": ["not", "an", "object"]}"#;
        let manifest = parse_manifest("weird/package.json", body, "cc");
        assert!(manifest.problems.iter().any(|p| p.contains("'name'")));
        assert!(manifest.problems.iter().any(|p| p.contains("'main'")));
        assert!(manifest
            .problems
            .iter()
            .any(|p| p.contains("'dependencies'")));
        assert!(manifest.name.is_none());
        assert!(manifest.dependencies.is_empty());
    }

    #[test]
    fn module_field_is_used_when_main_is_absent() {
        let body = br#"{"name": "x", "module": "dist/index.mjs"}"#;
        let manifest = parse_manifest("p.json", body, "dd");
        assert_eq!(manifest.entry_point(), Some("dist/index.mjs"));
    }
}
