# 50-Point Rust, Solana (Anchor/BPF) & ZK-SNARK (Groth16/R1CS) Security Audit Checklist

Use this battle-tested checklist before deploying Solana programs, cross-chain bridges, or Zero-Knowledge circuits to mainnet or submitting to paid bug bounty competitions (Immunefi, Code4rena, Sherlock, Cantina).

---

## Part I: Solana BPF & Anchor Account Validation (Points 1–15)
1. **[CRITICAL] Signer Verification (`SOL-001`)**: Every privileged instruction verifies `account.is_signer` or uses Anchor `Signer<'info>`.
2. **[CRITICAL] Account Owner Verification**: Raw `AccountInfo` deserialization explicitly verifies `account.owner == program_id` or expected SPL Token program ID.
3. **[CRITICAL] Arbitrary CPI Program Injection**: Cross-Program Invocations (`invoke` / `invoke_signed`) validate the target `program_id` against a hardcoded constant (`spl_token::ID`).
4. **[HIGH] Canonical PDA Bump Validation (`SOL-003`)**: PDAs are derived with `find_program_address` on initialization and verified against the stored canonical bump on subsequent calls.
5. **[HIGH] PDA Seed Collision & Domain Separation**: Variable-length byte slices in PDA seeds include explicit domain prefixes and length delimiters so `["pool", "ab", "c"]` cannot collide with `["pool", "a", "bc"]`.
6. **[HIGH] Account Re-Initialization / Discriminator Check**: Initialization instructions reject already-initialized accounts (Anchor 8-byte discriminator != 0).
7. **[HIGH] Closing Account Revival Attack**: Account closure zeroes all data bytes, transfers lamports safely, and sets the closed discriminator before instruction exit.
8. **[HIGH] Duplicate Mutable Accounts**: Instructions accepting two mutable accounts of the same type (`from_vault`, `to_vault`) verify `from_vault.key() != to_vault.key()`.
9. **[MEDIUM] Sysvar Address Spoofing**: Instructions reading `Rent`, `Clock`, or `Instructions` sysvars verify the canonical sysvar pubkey instead of trusting arbitrary accounts.
10. **[MEDIUM] Token Account Mint & Authority Mismatch**: SPL Token vaults verify both `.mint == expected_mint` and `.owner == expected_pda_authority`.
11. **[MEDIUM] SPL Token-2022 Transfer Fee / Hook Accounting**: Vault accounting checks actual post-transfer vault balance delta (`balance_after - balance_before`) rather than assuming `amount` arrived intact.
12. **[MEDIUM] Remaining Accounts Validation**: Any accounts read from `ctx.remaining_accounts` undergo full owner, discriminator, and key binding checks.
13. **[LOW] Rent-Exemption Enforcement**: State size reallocations (`AccountInfo::realloc`) verify sufficient lamports for rent exemption and cap maximum growth.
14. **[LOW] Freeze Authority & Close Authority Checks**: Protocol vaults reject SPL token accounts that have an external `close_authority` or unexpected `freeze_authority`.
15. **[LOW] Instruction Introspection Replay**: Ed25519 / Secp256k1 precompile introspection binds to a specific instruction index and prevents signature reuse across multiple inner instructions.

---

## Part II: Rust Integer Math, Precision & State Machine Invariants (Points 16–30)
16. **[HIGH] Signed `.abs()` Overflow on `i64::MIN` (`SOL-002`)**: Never call `.abs()` on signed integers (`i64`, `i128`); use `.unsigned_abs()` or `.checked_abs()`.
17. **[HIGH] Checked Arithmetic Everywhere**: All token balance, share, fee, and timestamp calculations use `checked_add`, `checked_sub`, `checked_mul`, `checked_div`.
18. **[HIGH] Division Before Multiplication Precision Loss**: Always compute `a.checked_mul(b)?.checked_div(c)?` (using `u128` intermediates) instead of `(a / c) * b`.
19. **[HIGH] Rounding Direction Favors Protocol Vault**: Deposit/mint calculations round **down** (`floor`) shares issued; withdrawal/borrow obligations round **up** (`ceil`).
20. **[HIGH] First-Depositor Vault Share Inflation Attack**: LP/share vaults mint minimum dead shares or use virtual offset reserves `(assets + 1) / (shares + 10^offset)`.
21. **[MEDIUM] Unsafe Cast Truncation (`as u64`, `as u32`)**: Replace lossy `as` casts with `u64::try_from(val).map_err(|_| ErrorCode::Overflow)?`.
22. **[MEDIUM] Out-of-Bounds Slice Indexing**: Replace `slice[idx]` with `slice.get(idx).ok_or(ErrorCode::InvalidIndex)?` in all on-chain parsers.
23. **[MEDIUM] Timestamp Drift & Slot Manipulation**: Enforce monotonic `clock.unix_timestamp >= last_update_ts` checks and avoid sub-second fairness assumptions.
24. **[MEDIUM] Fee Basis Points Upper Bound**: Protocol admin setters validate `fee_bps <= MAX_FEE_BPS` (e.g., `<= 10_000`) so fees can never exceed 100%.
25. **[LOW] Floating-Point Determinism Prohibition**: Never use `f32`/`f64` in consensus, smart contract, or financial accounting paths.
26. **[LOW] Unbounded Vector Iteration / CU Exhaustion**: Cap on-chain array/queue lengths so cleanup or settlement instructions can never exceed Solana's 1.4M Compute Unit limit.
27. **[LOW] Two-Step Admin / Authority Transfer**: Privileged `authority` rotation requires `propose_authority` followed by `accept_authority` by the new key.
28. **[LOW] Emergency Pause Granularity**: Pause flags block deposits/borrows without permanently trapping user withdrawals or liquidations unless explicitly intended.
29. **[LOW] Event Emission Integrity**: On-chain events log post-fee, post-slippage actual amounts rather than unvalidated user input parameters.
30. **[LOW] Borsh Deserialization Trailing Bytes**: Ensure custom deserializers reject trailing garbage bytes (`deserialize_reader` vs exact slice consumption).

---

## Part III: Zero-Knowledge Circuits (Groth16 / Plonk / R1CS) & Bridge Soundness (Points 31–50)
31. **[CRITICAL] Unconstrained Witness Variables (`ZK-001`)**: Every witness allocated via `alloc_witness` / `new_witness_variable` appears in at least one non-trivial R1CS multiplication/linear constraint.
32. **[CRITICAL] Assigned-But-Not-Constrained Gadget Outputs**: Custom hints (`|--` in Circom / witness closures in Arkworks/Bellman) are followed immediately by `===` / `cs.enforce(...)`.
33. **[CRITICAL] Non-Canonical Field Element Inputs (`ZK-002`)**: Public inputs and serialized proof elements are verified to be strictly `< r` (BN254 scalar field modulus) to prevent proof/nullifier aliasing.
34. **[CRITICAL] Missing Public Input Binding in Transcript / Proof**: Recipient address, relayer fee, chain ID, and withdrawal amount are bound as public inputs (or squared inside the circuit) so frontrunners cannot swap the recipient.
35. **[CRITICAL] Nullifier Domain Separation (`ZK-003`)**: Nullifier hashes include `domain_tag || chain_id ||program_id || leaf_index || secret` to prevent cross-epoch or cross-chain replay.
36. **[HIGH] Merkle Tree Path Index Bit Constraint**: Each path direction selector `b_i` in a Merkle proof is constrained to boolean `b_i * (1 - b_i) = 0`.
37. **[HIGH] Poseidon / Pedersen Hash Arity & Padding**: Variable-length inputs to Poseidon sponge include domain-separated capacity initialization so different input lengths cannot collide.
38. **[HIGH] Field Overflow in Range Checks**: `<` or `<=` comparisons in prime fields decompose operands into `N`-bit limbs and constrain each bit `b * (1 - b) = 0` before comparing.
39. **[HIGH] Division-by-Zero Witness Inverse**: Whenever computing `inv = x.inverse()`, enforce `x * inv = 1` (or `x * (1 - is_zero) = 0` in zero-multiplexer gadgets).
40. **[HIGH] Subgroup Membership Check on G1/G2 Points**: Custom Groth16 verifiers verify that proof points `(A, B, C)` lie on the curve and in the prime-order subgroup.
41. **[HIGH] Frozen Heart / Fiat-Shamir Transcript Completeness**: Non-interactive challenges hash all public parameters, commitment points, and public inputs in deterministic order.
42. **[HIGH] Bridge Co-Signer Quorum & Duplicate Signer Check**: Multi-validator bridge payloads deduplicate signer pubkeys before counting quorum (`signers.len() >= threshold`).
43. **[HIGH] Native vs SPL Asset Substitution in Bridge Co-Signing**: Co-sign payload hashes bind both `asset_type` (`NativeSOL` vs `SPL(mint_pubkey)`) and `decimals`.
44. **[MEDIUM] Historical Merkle Root Ring-Buffer Expiry**: Zero-knowledge withdrawal pools validate that the referenced `merkle_root` exists in the active ring buffer and is not zero/uninitialized.
45. **[MEDIUM] Trusted Setup Toxic Waste / Verification Key Pinning**: On-chain verifier pins the exact verification key constants (`alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`, `gamma_abc_g1`) as immutable constants.
46. **[MEDIUM] Batch Verification Random Linear Combination**: Batch Groth16 verification samples non-zero random scalars `r_i` from a CSPRNG so invalid proofs cannot cancel each other out.
47. **[MEDIUM] Equivocator Slash & Permanent Ban Enforcement**: Consensus/bridge nodes caught double-signing are permanently excluded from future committee selection.
48. **[LOW] Witness Generation Panic Safety**: Prover witness closures return `SynthesisError::AssignmentMissing` instead of panicking on `unwrap()` when given malformed inputs.
49. **[LOW] Endianness Consistency Between Rust & Circuit**: Big-integer conversions (`to_bytes_le` vs `to_bytes_be`) match identically between the on-chain Solana program and the R1CS circuit.
50. **[LOW] Deterministic Unit Test Coverage for Malicious Prover**: Every circuit test suite includes a negative test that mutates a witness value directly and asserts `cs.is_satisfied() == false`.
