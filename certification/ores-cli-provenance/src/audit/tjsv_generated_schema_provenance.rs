use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::json;
use walkdir::WalkDir;

use crate::model::{CommandReport, Finding};

use super::RepositoryAuditOptions;

const MAX_AUTOMATION_FILES: usize = 256;
const MAX_AUTOMATION_BYTES: u64 = 1024 * 1024;
const MAX_AUTOMATION_DEPTH: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    AuthoredSchema,
    GeneratedSchema,
}

struct ProvenanceAudit {
    findings: Vec<Finding>,
    inspected: usize,
}

pub(super) fn augment_tjsv_generated_schema_provenance_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let audit = audit_generated_schema_provenance(&options.path);
    for finding in audit.findings {
        report.push(finding);
    }
    report.insert_metadata(
        "tjsvGeneratedSchemaProvenanceFilesInspected",
        json!(audit.inspected),
    );
    report
}

fn audit_generated_schema_provenance(root: &Path) -> ProvenanceAudit {
    let mut findings = Vec::new();
    let mut candidates = Vec::new();

    for relative in [".github/workflows", "scripts", "tools"] {
        let directory = root.join(relative);
        if !directory.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&directory)
            .follow_links(false)
            .max_depth(MAX_AUTOMATION_DEPTH)
            .sort_by_file_name()
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    findings.push(
                        Finding::error(
                            "tjsv-provenance-source-unreadable",
                            "repository automation could not be traversed while checking generated-schema provenance",
                        )
                        .with_target(relative),
                    );
                    continue;
                }
            };
            if entry.file_type().is_dir() {
                continue;
            }
            if entry.file_type().is_symlink() {
                findings.push(
                    Finding::error(
                        "tjsv-provenance-source-symlink",
                        "TJSV provenance automation must not be supplied through a symlink",
                    )
                    .with_target(display_relative(root, entry.path())),
                );
                continue;
            }
            if is_automation_file(entry.path()) {
                candidates.push(entry.path().to_path_buf());
            }
            if candidates.len() > MAX_AUTOMATION_FILES {
                findings.push(Finding::error(
                    "tjsv-provenance-scan-limit",
                    "TJSV provenance automation exceeds the bounded file-count limit",
                ));
                break;
            }
        }
    }

    for name in [
        "package.json",
        "Makefile",
        "makefile",
        "Justfile",
        "justfile",
        ".zpkg.toml",
    ] {
        let path = root.join(name);
        if path.is_file() && !candidates.contains(&path) {
            candidates.push(path);
        }
    }

    candidates.sort();
    candidates.dedup();
    if candidates.len() > MAX_AUTOMATION_FILES {
        candidates.truncate(MAX_AUTOMATION_FILES);
    }

    let mut inspected = 0usize;
    for path in candidates {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                findings.push(
                    Finding::error(
                        "tjsv-provenance-source-unreadable",
                        "TJSV provenance automation is not readable",
                    )
                    .with_target(display_relative(root, &path)),
                );
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            findings.push(
                Finding::error(
                    "tjsv-provenance-source-unsafe",
                    "TJSV provenance automation must be a regular non-symlink file",
                )
                .with_target(display_relative(root, &path)),
            );
            continue;
        }
        if metadata.len() > MAX_AUTOMATION_BYTES {
            findings.push(
                Finding::error(
                    "tjsv-provenance-source-too-large",
                    "TJSV provenance automation exceeds the bounded source-size limit",
                )
                .with_target(display_relative(root, &path)),
            );
            continue;
        }
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(_) => {
                findings.push(
                    Finding::error(
                        "tjsv-provenance-source-invalid-utf8",
                        "TJSV provenance automation must be valid UTF-8",
                    )
                    .with_target(display_relative(root, &path)),
                );
                continue;
            }
        };
        inspected += 1;
        scan_source(root, &path, &source, &mut findings);
    }

    ProvenanceAudit {
        findings,
        inspected,
    }
}

fn scan_source(root: &Path, path: &Path, source: &str, findings: &mut Vec<Finding>) {
    let mut bindings = BTreeMap::<String, BindingKind>::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some((name, value)) = parse_assignment(line) {
            if mentions_authored_schema(value) {
                bindings.insert(name.to_owned(), BindingKind::AuthoredSchema);
            } else if mentions_generated_schema(value) {
                bindings.insert(name.to_owned(), BindingKind::GeneratedSchema);
            }
        }

        if !looks_like_copy_or_rewrite(line) {
            continue;
        }

        let has_authored = mentions_authored_schema(line)
            || line_mentions_binding(line, &bindings, BindingKind::AuthoredSchema);
        let has_generated = mentions_generated_schema(line)
            || line_mentions_binding(line, &bindings, BindingKind::GeneratedSchema);

        if has_authored && has_generated {
            findings.push(
                Finding::error(
                    "tjsv-generated-schema-provenance-violation",
                    "authored JSON Schema and TypeSpec-generated Schema B must not be copied or rewritten into one another; Schema B must come from the TypeSpec compiler/TJSV",
                )
                .with_target(display_relative(root, path))
                .with_detail("line", json!(index + 1)),
            );
        }
    }
}

fn parse_assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_prefix("export ").unwrap_or(line).trim();
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    let name = name
        .strip_prefix("$env:")
        .or_else(|| name.strip_prefix('$'))
        .unwrap_or(name)
        .trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    Some((name, value.trim()))
}

fn line_mentions_binding(
    line: &str,
    bindings: &BTreeMap<String, BindingKind>,
    expected: BindingKind,
) -> bool {
    bindings.iter().any(|(name, kind)| {
        *kind == expected
            && (line.contains(&format!("${name}"))
                || line.contains(&format!("${{{name}}}"))
                || line.contains(&format!("$env:{name}"))
                || line.contains(&format!("%{name}%")))
    })
}

fn schema_path_fragments(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '\'' | '"' | '(' | ')' | ',' | ';' | '=' | '>' | '<' | '[' | ']' | '{' | '}'
                )
        })
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| fragment.to_ascii_lowercase().replace('\\', "/"))
}

fn is_generated_schema_fragment(fragment: &str) -> bool {
    fragment.contains("typespec.generated.schema.json")
        || fragment.contains("generated.schema.json")
        || fragment.contains("generated_schema")
        || fragment.contains("generated-schema")
        || fragment.contains("typespec-generated")
        || fragment.contains(".typespec-json-schema-validator/generated")
}

fn mentions_authored_schema(value: &str) -> bool {
    schema_path_fragments(value).any(|fragment| {
        !is_generated_schema_fragment(&fragment)
            && (fragment.contains("authored.schema.json")
                || fragment.contains("contract.schema.json")
                || ((fragment.contains("contracts/") || fragment.contains("json-schema/"))
                    && fragment.contains(".schema.json")))
    })
}

fn mentions_generated_schema(value: &str) -> bool {
    schema_path_fragments(value).any(|fragment| is_generated_schema_fragment(&fragment))
}

fn looks_like_copy_or_rewrite(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let copy_call = [
        " cp ",
        "cp ",
        ": cp ",
        "/bin/cp ",
        "/usr/bin/cp ",
        " mv ",
        "mv ",
        ": mv ",
        " rsync ",
        "rsync ",
        "install ",
        " dd ",
        "dd ",
        "copy-item",
        "move-item",
        "shutil.copy",
        "copyfile",
        "copy_file",
        "fs.copy",
        "std::fs::copy",
        "writefile",
        "write_file",
        "fs::write",
        "os.writefile",
        "set-content",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let rewrite = lower.contains('>')
        && ["cat ", "sed ", "awk ", "jq ", "yq ", "printf ", "echo "]
            .iter()
            .any(|needle| lower.contains(needle));
    let tee = lower.contains("tee ") || lower.contains(" tee");
    copy_call || rewrite || tee
}

fn is_automation_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if matches!(name, "Makefile" | "makefile" | "Justfile" | "justfile") {
        return true;
    }
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some(
            "yml"
                | "yaml"
                | "sh"
                | "bash"
                | "zsh"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "mts"
                | "cts"
                | "py"
                | "rs"
                | "toml"
                | "json"
        )
    )
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::audit_generated_schema_provenance;

    fn write_workflow(source: &str) -> tempfile::TempDir {
        let directory = tempdir().expect("temporary directory");
        let workflows = directory.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflow directory");
        fs::write(workflows.join("contracts.yml"), source).expect("workflow source");
        directory
    }

    fn codes(source: &str) -> Vec<String> {
        let directory = write_workflow(source);
        audit_generated_schema_provenance(directory.path())
            .findings
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }

    fn has_provenance_violation(findings: &[String]) -> bool {
        findings
            .iter()
            .any(|code| code == "tjsv-generated-schema-provenance-violation")
    }

    #[test]
    fn canonical_tjsv_check_with_both_authorities_is_allowed() {
        let findings = codes(
            "run: tjsv check --typespec contracts/example/main.tsp --schema contracts/example/authored.schema.json --output-dir $RUNNER_TEMP/typespec-generated\n",
        );
        assert!(!has_provenance_violation(&findings));
    }

    #[test]
    fn direct_authored_to_generated_copy_is_rejected() {
        let findings = codes(
            "run: cp contracts/example/authored.schema.json $RUNNER_TEMP/typespec.generated.schema.json\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn variable_indirected_copy_is_rejected() {
        let findings = codes(
            "run: |\n  AUTHORED=contracts/example/authored.schema.json\n  GENERATED=$RUNNER_TEMP/typespec.generated.schema.json\n  cp \"$AUTHORED\" \"$GENERATED\"\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn powershell_variable_indirected_copy_is_rejected() {
        let findings = codes(
            "run: |\n  $AUTHORED = 'contracts/example/authored.schema.json'\n  $GENERATED = '.typespec-json-schema-validator/generated/typespec.generated.schema.json'\n  Copy-Item $AUTHORED $GENERATED\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn dd_copy_between_authority_and_generated_lanes_is_rejected() {
        let findings = codes(
            "run: dd if=contracts/example/authored.schema.json of=.typespec-json-schema-validator/generated/typespec.generated.schema.json\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn read_write_api_rewrite_between_lanes_is_rejected() {
        let findings = codes(
            "run: node -e \"fs.writeFileSync('.typespec-json-schema-validator/generated/typespec.generated.schema.json', fs.readFileSync('contracts/example/authored.schema.json'))\"\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn programmatic_copy_between_authority_and_generated_lanes_is_rejected() {
        let findings = codes(
            "run: node -e \"fs.copyFileSync('contracts/example/authored.schema.json', '.typespec-json-schema-validator/generated/typespec.generated.schema.json')\"\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn commented_copy_example_is_ignored() {
        let findings = codes(
            "# cp contracts/example/authored.schema.json $RUNNER_TEMP/typespec.generated.schema.json\n// fs.copyFileSync('contracts/example/authored.schema.json', 'typespec.generated.schema.json')\n",
        );
        assert!(!has_provenance_violation(&findings));
    }

    #[test]
    fn generated_to_authored_copy_is_also_rejected() {
        let findings = codes(
            "run: cp $RUNNER_TEMP/typespec.generated.schema.json contracts/example/authored.schema.json\n",
        );
        assert!(has_provenance_violation(&findings));
    }

    #[test]
    fn generated_schema_inside_contracts_is_not_misclassified_as_authored() {
        let findings = codes(
            "run: cp contracts/example/typespec.generated.schema.json $RUNNER_TEMP/archive.json\n",
        );
        assert!(!has_provenance_violation(&findings));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_automation_source_fails_closed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let workflows = directory.path().join(".github/workflows");
        fs::create_dir_all(&workflows).expect("workflow directory");
        let outside = directory.path().join("outside.yml");
        fs::write(&outside, "run: true\n").expect("outside source");
        symlink(&outside, workflows.join("contracts.yml")).expect("workflow symlink");

        let findings = audit_generated_schema_provenance(directory.path()).findings;
        assert!(findings
            .iter()
            .any(|finding| finding.code == "tjsv-provenance-source-symlink"));
    }
}
