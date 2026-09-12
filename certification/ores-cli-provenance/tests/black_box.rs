use std::fs;

use ores_cli_schema_b_provenance_cert::audit::certify_repository;
use tempfile::tempdir;

fn audit_workflow(source: &str) -> Vec<String> {
    let root = tempdir().expect("temporary repository");
    let workflows = root.path().join(".github/workflows");
    fs::create_dir_all(&workflows).expect("workflow directory");
    fs::write(workflows.join("contracts.yml"), source).expect("workflow source");
    certify_repository(root.path().to_path_buf())
        .findings
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

fn has_provenance_violation(codes: &[String]) -> bool {
    codes
        .iter()
        .any(|code| code == "tjsv-generated-schema-provenance-violation")
}

#[test]
fn canonical_dual_authority_tjsv_flow_is_admitted() {
    let codes = audit_workflow(
        "run: tjsv check --typespec contracts/example/main.tsp --schema contracts/example/authored.schema.json --output-dir .typespec-json-schema-validator/generated\n",
    );
    assert!(!has_provenance_violation(&codes));
}

#[test]
fn powershell_schema_a_to_schema_b_spoof_is_rejected() {
    let codes = audit_workflow(
        "run: |\n  $AUTHORED = 'contracts/example/authored.schema.json'\n  $GENERATED = '.typespec-json-schema-validator/generated/typespec.generated.schema.json'\n  Copy-Item $AUTHORED $GENERATED\n",
    );
    assert!(has_provenance_violation(&codes));
}

#[test]
fn dd_schema_a_to_schema_b_spoof_is_rejected() {
    let codes = audit_workflow(
        "run: dd if=contracts/example/authored.schema.json of=.typespec-json-schema-validator/generated/typespec.generated.schema.json\n",
    );
    assert!(has_provenance_violation(&codes));
}

#[test]
fn read_write_api_schema_a_to_schema_b_spoof_is_rejected() {
    let codes = audit_workflow(
        "run: node -e \"fs.writeFileSync('.typespec-json-schema-validator/generated/typespec.generated.schema.json', fs.readFileSync('contracts/example/authored.schema.json'))\"\n",
    );
    assert!(has_provenance_violation(&codes));
}
