# AGENTS

> **Project mission (stable):** High‑performance, AI‑integrated, zk‑privacy Layer‑1 Blockchain — a production‑ready Rust‑based PoS chain with MEV‑resistant commit–reveal ordering, smart‑contract accounts, meta‑transactions, and validator‑driven AI scoring with zero‑knowledge proofs. Targets **50k+ TPS** and **≤12s finality**.

This document is a **generic, future‑proof guide** for AI coding agents (and humans) contributing to this repository. It avoids repository‑specific names so it remains valid even as internal modules evolve.

---

## 1) Scope & Responsibilities

An AI agent working in this repo should:

- **Understand high‑level goals** (PoS L1, commit–reveal anti‑MEV, privacy via ZK, AI scores posted as proofs).
- **Propose and implement localized changes** that improve correctness, safety, performance, or developer experience.
- **Preserve public behavior and invariants** unless a change is explicitly requested and approved.
- **Write tests first (or alongside)** for every behavior change or new feature.
- **Document decisions** in short, durable notes (comments or ADR-style markdown) that avoid implementation trivia.

Out of scope (unless explicitly requested): feature creep, protocol redesigns, or changes that require hard forks.

---

## 2) Design Principles (Stable)

- **Determinism**: Consensus‑affecting logic must be deterministic across nodes.
- **Idempotence**: Maintenance routines (e.g., pruning/revalidation) should be safe to run multiple times.
- **Separation of concerns**: Consensus, execution, mempool, networking, and fee logic evolve independently with clear interfaces.
- **Minimal coupling**: Avoid cross‑layer shortcuts. Interactions occur via small, read‑only views or messages.
- **Backpressure & safety**: Prefer bounded queues, timeouts, and saturating arithmetic. Never block holding a wide lock.
- **Observability**: Expose metrics/telemetry around throughput, latency, and reasons for drops/prunes.
- **Upgradeability**: Changes should be additive when possible; breaking changes require explicit migration plans.

---

## 3) Architecture (Abstract)

The chain is conceptually split into:

1. **Consensus (PoS)**
   - Proposer/validator rotation; votes; finality within target window (≤12s).
   - Signature aggregation envisioned for scalability.

2. **Mempool (MEV‑resistant)**
   - **Commit** (blinded), **Avail** (data availability), **Reveal** (plaintext execution) lanes.
   - Admission filters, per‑account caps, ready‑at and TTL semantics.

3. **Execution / State Machine**
   - Smart‑contract accounts, meta‑transactions, gas/fee accounting, receipts.

4. **Fees**
   - Per‑lane base fees with elasticity (EIP‑1559‑style dynamics or equivalent). Exact policy may evolve.

5. **AI & ZK Attestations**
   - Off‑chain AI computes per‑address metrics (credit/participation/reputation).
   - On‑chain verifier checks zero‑knowledge proofs and records attestations.

6. **Networking**
   - Gossip/broadcast topics for lanes and consensus messages; DoS-aware limits.

> **Note:** Concrete module/type names are intentionally omitted. Agents should discover current names in the codebase before editing.

---

## 4) Invariants (Must Hold)

- **Commit–Reveal Semantics**
  - Each **Reveal** must correspond to a prior **Commit** (one‑to‑one); mismatches are rejected.
  - Commits have a **TTL**; Reveals have a **window**; expired items are pruned.
  - Inclusion list or readiness rules (if present) act as hard constraints during selection.

- **Selection & Maintenance Order**
  - **Select → Build Block → Apply → Mark Included → Revalidate Affordability → Evict Stale**.
  - Marking included items precedes any pruning to avoid double counting and unnecessary scans.

- **Affordability**
  - Transactions must be affordable relative to **current** per‑lane base fees and sender resources.

- **Safety on Reorgs**
  - Non‑canonical inclusions are reverted in the mempool subject to freshness and validity checks; maintenance re‑runs after reorg finalization.

- **Deterministic Limits**
  - Per‑lane limits (items per block, per‑account caps) are applied deterministically.

---

## 5) AI Scoring & ZK (Abstract Contract)

- **Request/Response Market**: Addresses may request validator‑provided scoring for a fee.
- **Off‑chain Compute**: Models and features stay off‑chain; outputs are commitments and proofs.
- **On‑chain Verification**: The chain stores a succinct attestation `(address, score_type, epoch, commitment)` with a proof verified by a standard SNARK/zkVM verifier.
- **Privacy**: No raw features or model internals are revealed on‑chain; only zero‑knowledge attestations.

Agents must not embed model weights, datasets, or private keys in the repository.

---

## 6) Performance Goals (Guidance)

- Target **50k+ TPS** under realistic configurations; keep hot paths allocation‑lean.
- Aim for **≤12s finality** by minimizing consensus rounds, message sizes, and verification overhead.
- Use batch verification, parallelizable execution, and pipelining where safe.

These are directional goals, not hard gates for every PR.

---

## 7) Contribution Rules (Stable)

- **Tests**: Every change affecting logic must include unit/integration tests. Prefer property/fuzz tests for invariants.
- **Lints & Style**: `cargo test` must pass.
- **Docs**: Add/refresh comments and short markdown notes for new concepts or invariants (keep generic).
- **Benchmarks (when relevant)**: Provide micro/macro benchmarks or explain measured impact.
