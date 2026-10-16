#!/usr/bin/env python3
"""
Unit test suite (`test_scanner.py`) for the Rust, Solana & ZK-SNARK Security Audit Scanner Kit.
"""

from __future__ import annotations

import unittest

from solana_zk_scanner import SolanaZkAuditScanner


class TestSolanaZkScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = SolanaZkAuditScanner()

    def test_detects_missing_signer_and_i64_abs_and_noncanonical_pda(self) -> None:
        vulnerable_solana_rs = """
        pub fn emergency_withdraw(
            program_id: &Pubkey,
            authority: AccountInfo,
            delta_amount: i64,
        ) -> ProgramResult {
            let abs_val = delta_amount.abs();
            let pda = Pubkey::create_program_address(&[b"vault", &[255]], program_id)?;
            Ok(())
        }
        """
        findings = self.scanner.scan_source(vulnerable_solana_rs, "vault.rs")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SOL-001", rule_ids)
        self.assertIn("SOL-002", rule_ids)
        self.assertIn("SOL-003", rule_ids)

    def test_detects_unconstrained_zk_witness_and_mod_order(self) -> None:
        vulnerable_circuit_rs = """
        pub fn synthesize_withdraw(cs: &mut ConstraintSystem, raw_input: &[u8]) {
            let secret_nullifier = cs.alloc_witness(|| Ok(Fr::from_le_bytes_mod_order(raw_input)));
        }
        """
        findings = self.scanner.scan_source(vulnerable_circuit_rs, "circuit.rs")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ZK-001", rule_ids)
        self.assertIn("ZK-002", rule_ids)

    def test_safe_code_produces_zero_findings(self) -> None:
        safe_rs = """
        pub fn safe_withdraw(
            program_id: &Pubkey,
            authority: Signer<'info>,
            delta_amount: i64,
            cs: &mut ConstraintSystem,
        ) -> ProgramResult {
            require!(authority.is_signer, ErrorCode::Unauthorized);
            let abs_val = delta_amount.unsigned_abs();
            let (pda, bump) = Pubkey::find_program_address(&[b"vault"], program_id);
            let w = cs.alloc_witness(|| Ok(Fr::one()));
            cs.enforce(|| "bind witness", |lc| lc + w, |lc| lc + CS::one(), |lc| lc + w);
            Ok(())
        }
        """
        findings = self.scanner.scan_source(safe_rs, "safe_vault.rs")
        self.assertEqual(findings, [])

    def test_markdown_and_json_report_generation(self) -> None:
        code = "pub fn bad(admin: AccountInfo, x: i64) { let y = x.abs(); }"
        findings = self.scanner.scan_source(code, "bad.rs")
        md = self.scanner.to_markdown_report(findings)
        js = self.scanner.to_json_report(findings)
        self.assertIn("SOL-001", md)
        self.assertIn("SOL-002", js)


if __name__ == "__main__":
    unittest.main()
