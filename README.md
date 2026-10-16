# Rust, Solana (Anchor/BPF) & ZK-SNARK (Groth16/R1CS) Security Audit Scanner & 50-Point Checklist Kit (v1.0)

A zero-dependency static security analyzer (`solana_zk_scanner.py`) and 50-point audit checklist (`AUDIT_CHECKLIST_50_POINTS.md`) engineered for Solana smart contract developers, ZK-SNARK circuit engineers, and Web3 bug bounty hunters.

---

## Included Files
1. **`solana_zk_scanner.py`**: Automated static pattern scanner detecting:
   - `SOL-001` (CRITICAL): Missing Signer Verification on Privileged `AccountInfo`
   - `SOL-002` (HIGH): Signed Integer `.abs()` Panic / Two's Complement Overflow on `i64::MIN`
   - `SOL-003` (HIGH): Non-Canonical PDA Bump Derived via `create_program_address`
   - `ZK-001` (CRITICAL): Unconstrained R1CS Witness Allocation (`alloc_witness` without `cs.enforce`)
   - `ZK-002` (HIGH): Non-Canonical Scalar Field Deserialization (`from_le_bytes_mod_order` / `from_bytes_unchecked`)
2. **`AUDIT_CHECKLIST_50_POINTS.md`**: Complete 50-point pre-audit checklist covering Solana BPF/Anchor account validation, integer math invariants, and Groth16/R1CS circuit soundness.
3. **`test_scanner.py`**: Automated `pytest` / `unittest` verification suite (`4/4 PASSED`).

---

## Running the Test Suite
```bash
pytest test_scanner.py -v
```
