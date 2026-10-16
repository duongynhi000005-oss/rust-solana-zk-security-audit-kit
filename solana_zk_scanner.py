#!/usr/bin/env python3
"""
Rust / Solana / ZK-SNARK Static Security Audit Scanner (`solana_zk_scanner.py`)
Part of the Rust, Solana & ZK-SNARK Security Audit Scanner & 50-Point Checklist Kit (v1.0).

Scans Rust source files (.rs) for high-severity Solana BPF/Anchor and Groth16/R1CS
cryptographic circuit vulnerabilities and generates a Markdown/JSON audit report.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True)
class AuditFinding:
    rule_id: str
    severity: str
    title: str
    file_path: str
    line_number: int
    snippet: str
    remediation: str


class SolanaZkAuditScanner:
    """
    Deterministic static pattern analyzer for Rust smart contracts (Solana/Anchor/Soroban)
    and Zero-Knowledge R1CS/Groth16 circuits.
    """

    def scan_source(self, source_code: str, file_path: str = "contract.rs") -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        lines = source_code.splitlines()

        has_signer_check = bool(
            re.search(r"\bis_signer\b|\bSigner\s*<|require!\s*\([^)]*is_signer", source_code)
        )
        has_witness_alloc = False
        witness_lines: List[tuple[int, str]] = []
        has_r1cs_enforce = bool(
            re.search(r"\benforce\s*\(|\benforce_constraint\s*\(|\bcs\.enforce", source_code)
        )

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            # Rule SOL-001: Raw AccountInfo used for authority/admin/user without signer verification
            if re.search(r"\b(authority|admin|operator|signer)\s*:\s*AccountInfo\b", line):
                if not has_signer_check:
                    findings.append(
                        AuditFinding(
                            rule_id="SOL-001",
                            severity="CRITICAL",
                            title="Missing Signer Verification on Privileged AccountInfo",
                            file_path=file_path,
                            line_number=idx,
                            snippet=line,
                            remediation="Use Anchor `Signer<'info>` or explicitly check `if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }`.",
                        )
                    )

            # Rule SOL-002: i64::MIN.abs() or unchecked u64 arithmetic in balance/amount logic
            if re.search(r"\.abs\s*\(\s*\)", line) and not re.search(r"unsigned_abs|checked_abs", line):
                findings.append(
                    AuditFinding(
                        rule_id="SOL-002",
                        severity="HIGH",
                        title="Signed Integer `.abs()` Panic / Two's Complement Overflow on i64::MIN",
                        file_path=file_path,
                        line_number=idx,
                        snippet=line,
                        remediation="Replace `.abs()` with `.unsigned_abs()` or `.checked_abs().ok_or(ErrorCode::MathOverflow)?` to prevent panic on `i64::MIN`.",
                    )
                )

            # Rule SOL-003: Non-canonical PDA creation via create_program_address without bump validation
            if "create_program_address" in line and "find_program_address" not in source_code:
                findings.append(
                    AuditFinding(
                        rule_id="SOL-003",
                        severity="HIGH",
                        title="Non-Canonical PDA Bump Derived via `create_program_address`",
                        file_path=file_path,
                        line_number=idx,
                        snippet=line,
                        remediation="Derive or verify the canonical bump using `Pubkey::find_program_address` and store the canonical bump in the account state.",
                    )
                )

            # Track ZK witness allocations
            if re.search(r"\balloc_witness\b|\bnew_witness_variable\b", line):
                has_witness_alloc = True
                witness_lines.append((idx, line))

            # Rule ZK-002: Unchecked field element deserialization without canonical modulus bound
            if re.search(r"from_le_bytes_mod_order|from_bytes_unchecked", line):
                findings.append(
                    AuditFinding(
                        rule_id="ZK-002",
                        severity="HIGH",
                        title="Non-Canonical Scalar Field Deserialization (Malleable Proof Input)",
                        file_path=file_path,
                        line_number=idx,
                        snippet=line,
                        remediation="Reject byte representations >= field modulus `r` using canonical `Fr::from_CanonicalDeserialize` or explicit `< MODULUS` validation.",
                    )
                )

        # Rule ZK-001: Witness allocated without any R1CS constraint enforcement in the circuit
        if has_witness_alloc and not has_r1cs_enforce:
            first_line, first_snippet = witness_lines[0]
            findings.append(
                AuditFinding(
                    rule_id="ZK-001",
                    severity="CRITICAL",
                    title="Unconstrained R1CS Witness Allocation (Under-Constrained Circuit)",
                    file_path=file_path,
                    line_number=first_line,
                    snippet=first_snippet,
                    remediation="Bind every allocated witness variable inside `cs.enforce(...)` / `enforce_constraint(...)` so a malicious prover cannot forge arbitrary witness values.",
                )
            )

        return findings

    def scan_directory(self, root_dir: Path) -> List[AuditFinding]:
        all_findings: List[AuditFinding] = []
        for rs_file in sorted(root_dir.rglob("*.rs")):
            text = rs_file.read_text(encoding="utf-8", errors="ignore")
            rel = str(rs_file.relative_to(root_dir))
            all_findings.extend(self.scan_source(text, file_path=rel))
        return all_findings

    @staticmethod
    def to_markdown_report(findings: List[AuditFinding]) -> str:
        lines = [
            "# Rust / Solana / ZK-SNARK Automated Security Audit Report",
            "",
            f"- **Total Findings**: {len(findings)}",
            "",
        ]
        if not findings:
            lines.append("No static vulnerability patterns detected.")
            return "\n".join(lines)

        for idx, f in enumerate(findings, start=1):
            lines.extend(
                [
                    f"## [{f.rule_id}] ({f.severity}) {f.title} — Finding #{idx}",
                    f"- **Location**: `{f.file_path}:{f.line_number}`",
                    f"- **Vulnerable Snippet**: `{f.snippet}`",
                    f"- **Remediation**: {f.remediation}",
                    "",
                ]
            )
        return "\n".join(lines)

    @staticmethod
    def to_json_report(findings: List[AuditFinding]) -> str:
        return json.dumps([asdict(f) for f in findings], indent=2)
