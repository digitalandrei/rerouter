//! Guard against a MariaDB/MySQL split that bit us in production (2026-07):
//! `sqlx::query(...)` always uses the prepared-statement protocol, and MySQL
//! 8.x cannot prepare transaction-control statements — `PREPARE ... FROM
//! 'START TRANSACTION'` fails with error 1295 ("not supported in the prepared
//! statement protocol"), while MariaDB (dev/test) accepts it. The result was
//! user update/delete 500-ing only on the MySQL 8.4 deployment.
//!
//! Transaction control must go through sqlx's `begin()` / `commit()` /
//! `rollback()`, which use the text protocol. This lint scans the crate source
//! so the pattern cannot come back.

use std::path::{Path, PathBuf};

/// String literals that must never be issued through `sqlx::query*` calls.
/// Leading `"` anchors the match to the start of a literal.
const BANNED: &[&str] = &[
    "\"START TRANSACTION",
    "\"BEGIN\"",
    "\"COMMIT",
    "\"ROLLBACK",
    "\"SAVEPOINT",
    "\"RELEASE SAVEPOINT",
    "\"LOCK TABLES",
    "\"UNLOCK TABLES",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_transaction_control_via_prepared_statements() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&src, &mut files);
    assert!(!files.is_empty(), "no source files found under {src:?}");

    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source file");
        for (idx, line) in text.lines().enumerate() {
            if !line.contains("sqlx::query") {
                continue;
            }
            if let Some(banned) = BANNED.iter().find(|b| line.contains(*b)) {
                offenders.push(format!(
                    "{}:{}: {} inside a sqlx::query call",
                    file.display(),
                    idx + 1,
                    banned.trim_start_matches('"'),
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "transaction control must use sqlx begin()/commit()/rollback() (text \
         protocol); MySQL 8.x cannot prepare these statements (error 1295), so \
         sqlx::query(...) breaks on MySQL even though MariaDB accepts it:\n{}",
        offenders.join("\n"),
    );
}
