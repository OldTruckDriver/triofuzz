# PROBE: Pure Tree Search for Fuzzing

A specification for integrating UCT-based tree search into AFL++.

---

## 0. How to Use This Document

This is an implementation specification for an autonomous coding agent. Each section below is a concrete milestone. Do not skip ahead. After completing each milestone, run its validation checks. If validation fails, stop and diagnose; do not proceed by adjusting thresholds.

The codebase is implemented as a fork of AFL++ in C, not LibAFL. Maintain a small set of new source files plus targeted modifications to AFL++'s `fuzz_one()` and queue scheduling logic. Keep all PROBE-specific code in clearly marked sections so upstream merges remain feasible.

---

## 1. Research Position

PROBE rejects the formulation underlying existing online-learning fuzzers (MOPT, EcoFuzz, xFUZZ, MUFuzz, etc.). Those systems treat fuzzing as stochastic estimation over arms or states whose reward distributions can be predicted from past observations. This is a category error. Fuzzing is combinatorial exploration of a deterministic but unknown structure. Past observations describe what has been visited, not what future visits will reveal.

PROBE makes one strong commitment: **no prediction**. The algorithm never extrapolates from past data to future expected reward. It only records facts (which abstract states have been visited, how many times, with what observed reward) and uses UCB's mathematical structure to balance exploration against exploitation based on those facts alone.

The architectural invariant is: **tree search owns direction, AFL++ owns throughput, and nothing in the system tries to predict the future.**

This commitment removes entire categories of failure modes that plague online-learning fuzzers (non-stationary distribution drift, prior misspecification, transfer failure, training data contamination). It also rules out entire categories of mechanisms (learned priors, sliding windows over reward, change-point detection, Markov chain pretraining). The simplicity is the point.

---

## 2. System Architecture

### 2.1 Components

```
+------------------------------------------------------------+
|                    PROBE Controller (in AFL++)             |
|                                                            |
|   +------------------+      +-------------------------+    |
|   |  UCT Selector    |<---->| Tree (nodes, edges, Q,N)|    |
|   +------------------+      +-------------------------+    |
|           |                            ^                   |
|           v                            |                   |
|   +------------------+      +-------------------------+    |
|   | LSH Abstraction  |      | Snapshot / Telemetry    |    |
|   | (coverage->state)|      | (JSON dumps for visualizer)| |
|   +------------------+      +-------------------------+    |
+------------------------------------------------------------+
              |                          ^
              v                          |
+------------------------------------------------------------+
|              AFL++ Native Components (untouched)           |
|   - havoc mutator                                          |
|   - forkserver                                             |
|   - coverage shared memory map (64KB)                      |
|   - queue (used as physical seed storage)                  |
+------------------------------------------------------------+
```

### 2.2 Per-Iteration Data Flow

1. UCT Selector traverses the tree from root to a leaf using the UCB formula. The leaf points to a seed in AFL++'s queue.
2. AFL++ havoc mutator runs `k` mutations on that seed (`k` adaptive per Section 5).
3. After each execution, LSH Abstraction maps the post-execution coverage map to an abstract state ID.
4. New abstract states discovered during the rollout become new tree nodes attached to the leaf's path.
5. Reward (count of new edges discovered during the rollout batch) is backpropagated up the path, incrementing visit counts and value sums.
6. Loop.

No pretraining. No prior. No window. No restructuring. The tree only grows.

### 2.3 Architectural Invariants

The agent must enforce these throughout implementation. Violating any compromises the research contribution.

- **I1.** Total scheduler overhead must remain under 10% of vanilla AFL++ exec/s.
- **I2.** AFL++'s native havoc mutator is the rollout engine; do not replace or augment its operator selection.
- **I3.** No component shall maintain learned parameters across campaigns. Each campaign starts with an empty tree.
- **I4.** No component shall use observed reward to predict future reward distributions. Backprop only records observed facts.
- **I5.** All randomness must be seeded for bit-exact reproducibility.

If a proposed feature would violate I3 or I4, do not implement it. These are research commitments, not engineering preferences.

---

## 3. Project Layout

Fork AFL++ at a pinned commit (record commit hash in `docs/upstream.md`). Add the following structure:

```
AFLplusplus/
├── (existing AFL++ files)
├── include/
│   ├── probe-tree.h           # Tree data structure and UCB selection
│   ├── probe-abstraction.h    # LSH coverage abstraction
│   ├── probe-rollout.h        # Rollout batch management
│   └── probe-telemetry.h      # Snapshot and logging
├── src/
│   ├── probe-tree.c
│   ├── probe-abstraction.c
│   ├── probe-rollout.c
│   └── probe-telemetry.c
├── src/afl-fuzz-one.c         # MODIFIED: fuzz_one() integration
├── src/afl-fuzz-queue.c       # MODIFIED: scheduler hook
├── src/afl-fuzz-state.c       # MODIFIED: state init/teardown for tree
├── tools/
│   └── tree-visualizer/       # standalone web UI for snapshots
├── tests/
│   ├── unit/                  # tree, abstraction unit tests
│   └── integration/           # end-to-end smoke tests
├── scripts/
│   ├── build_probe.sh
│   ├── run_campaign.sh
│   └── compare_baselines.sh
├── docs/
│   ├── upstream.md            # pinned AFL++ commit
│   ├── design_notes.md
│   ├── abstraction_tuning.md
│   ├── baseline_results.md
│   ├── evaluation.md
│   └── snapshot_schema.md
└── data/
    ├── corpora/               # FuzzBench-style initial corpora
    └── adversarial/           # synthetic targets for paper motivation
```

All PROBE-specific changes in modified AFL++ files must be wrapped in `#ifdef PROBE_ENABLED ... #endif` blocks. The build system gets a `PROBE_BUILD=1` flag that toggles this.

---

## 4. Component Specifications

### 4.1 Tree (`probe-tree.h`, `probe-tree.c`)

#### Data Structures

```c
typedef uint64_t state_id_t;
typedef uint32_t node_id_t;
typedef uint32_t seed_id_t;

#define PROBE_INVALID_NODE 0xFFFFFFFFU

typedef struct probe_node {
    node_id_t   id;
    node_id_t   parent;
    node_id_t  *children;        // dynamic array
    uint32_t    n_children;
    uint32_t    cap_children;
    state_id_t  state_id;
    uint64_t    visit_count;     // N(s,a)
    double      value_sum;       // sum of rewards; Q(s,a) = value_sum / visit_count
    seed_id_t  *seed_ids;        // queue entry indices
    uint32_t    n_seeds;
    uint32_t    cap_seeds;
    uint32_t    depth;
} probe_node_t;

typedef struct probe_tree {
    probe_node_t  *nodes;        // dense array, indexed by node_id
    uint32_t       n_nodes;
    uint32_t       cap_nodes;
    node_id_t      root;
    state_id_t    *state_to_node_keys;   // hash table
    node_id_t     *state_to_node_vals;
    uint32_t       state_table_size;
    double         puct_c;       // exploration constant; default sqrt(2)
    uint64_t       rng_state;    // for tie-breaking, seeded
} probe_tree_t;
```

#### API

```c
probe_tree_t *probe_tree_new(double c, uint64_t seed);
void          probe_tree_free(probe_tree_t *t);

// Returns the leaf reached by UCB traversal and one of its seed IDs.
// On entry the tree must contain at least the root with seed entries attached.
void probe_tree_select(probe_tree_t *t,
                       node_id_t   *out_leaf,
                       seed_id_t   *out_seed);

// Called when a rollout discovers a new abstract state on the path.
// Returns the node id (existing or newly created).
node_id_t probe_tree_observe_state(probe_tree_t *t,
                                   node_id_t    parent,
                                   state_id_t   state);

// Attach a seed to an existing node (for new corpus entries).
void probe_tree_attach_seed(probe_tree_t *t,
                            node_id_t    node,
                            seed_id_t    seed);

// Backpropagate a reward up the path from leaf to root.
void probe_tree_backprop(probe_tree_t *t,
                         node_id_t    leaf,
                         double       reward);

// Serialize tree state to JSON for the visualizer. Allocates buffer.
char *probe_tree_snapshot_json(const probe_tree_t *t);

// Statistics accessors used by telemetry and tests.
uint32_t probe_tree_node_count(const probe_tree_t *t);
uint32_t probe_tree_max_depth(const probe_tree_t *t);
```

#### UCB Formula (Implementation Detail)

For a parent node `s` with children `a_1, ..., a_k`:

```
UCB(s, a) = (Q(a) / N(a)) + c * sqrt(ln(N(s)) / N(a))
```

with the convention that any child with `N(a) == 0` is selected first (standard UCT cold-start rule). Ties broken by seeded RNG. The exploration constant `c` defaults to `sqrt(2)` (the standard UCT value), configurable via `probe.toml`.

#### Implementation Notes

- Hash table for `state_id -> node_id` uses linear probing; size to `4 * expected_nodes`, doubled on load factor exceeding 0.5.
- Children arrays grow with `realloc` doubling; no free list.
- `value_sum` is double precision; for very long campaigns watch for accumulation error, but for 24-hour budgets this is not a real concern.
- No locks; the tree is owned by a single thread (the AFL++ main fuzzing thread). Multi-worker support is deferred (Section 9).

### 4.2 Abstraction (`probe-abstraction.h`, `probe-abstraction.c`)

This is the most consequential design decision in the entire system. Per Section 7, expect to spend significant pilot time tuning abstraction; do not commit to one variant prematurely.

#### Phase 1: Coverage-Frontier-Aware LSH

Asymmetric treatment of covered vs. uncovered edges, motivated by the observation that covered edges contribute less to "what's interesting now" than frontier edges.

```c
typedef struct probe_abstraction {
    // LSH parameters
    uint32_t  n_hashes;          // number of hash functions
    uint32_t  proj_dim;          // projected dimension per hash
    int8_t   *projection;        // n_hashes * proj_dim * map_size, values in {-1, 0, +1}
    uint32_t  map_size;          // AFL++ shared map size, typically 65536

    // Frontier weighting
    uint8_t  *covered_edges;     // bitmap of edges seen at least once globally
    double    frontier_weight;   // multiplier for uncovered-edge contribution; default 4.0
    double    covered_weight;    // multiplier for covered-edge contribution; default 1.0

    uint64_t  rng_seed;
} probe_abstraction_t;

probe_abstraction_t *probe_abstraction_new(uint32_t n_hashes,
                                           uint32_t proj_dim,
                                           uint32_t map_size,
                                           uint64_t seed);
void                 probe_abstraction_free(probe_abstraction_t *a);

// Computes abstract state ID. Updates `covered_edges` as a side effect.
state_id_t probe_abstract_state(probe_abstraction_t *a,
                                const uint8_t      *coverage_map);
```

The frontier-aware variant computes hash projections weighted by whether an edge has been globally covered before. Newly hit edges contribute `frontier_weight` times more to the hash than already-covered ones, so abstract states are more sensitive to frontier movement than to revisits of known territory.

#### Phase 2 (deferred to Section 8): Hierarchical Abstraction

If Phase 1's growth curves are unsatisfactory (M2 validation fails), revisit with a depth-dependent abstraction where tree nodes near the root use coarser LSH and nodes near leaves use finer LSH. Defer concrete design until pilot data is in hand.

### 4.3 Rollout Manager (`probe-rollout.h`, `probe-rollout.c`)

Wraps AFL++'s havoc execution and integrates abstract-state tracking into the per-execution path.

```c
typedef struct probe_rollout {
    probe_tree_t        *tree;
    probe_abstraction_t *abst;
    uint32_t             k_min;       // minimum rollout batch size
    uint32_t             k_max;       // maximum rollout batch size
    uint32_t             k_current;   // adapts per node, see Section 5
    uint64_t             total_executions;
    uint64_t             cold_start_budget;  // executions before UCT activates
} probe_rollout_t;

probe_rollout_t *probe_rollout_new(probe_tree_t        *tree,
                                   probe_abstraction_t *abst,
                                   uint32_t             k_min,
                                   uint32_t             k_max,
                                   uint64_t             cold_start);

// Run a rollout batch. Called from the modified fuzz_one() in afl-fuzz-one.c.
// `node` is the leaf returned by probe_tree_select.
// `seed` is the seed ID returned by probe_tree_select.
// Returns the cumulative reward (new edges) for this batch.
double probe_rollout_run(probe_rollout_t *r,
                         afl_state_t     *afl,    // AFL++ global state
                         node_id_t        node,
                         seed_id_t        seed);
```

The rollout manager is the only PROBE component that calls into AFL++'s mutation logic. It does so by invoking AFL++'s existing havoc functions (`fuzz_one_havoc` or its underlying primitives), passing the selected seed. After each execution within the batch, it reads the post-execution coverage map, calls `probe_abstract_state`, and records state transitions on the path.

### 4.4 Telemetry (`probe-telemetry.h`, `probe-telemetry.c`)

```c
typedef struct probe_telemetry {
    char    *output_dir;
    FILE    *iter_log;       // CSV: iteration, leaf_id, seed_id, reward, k
    uint64_t snapshot_interval_secs;
    time_t   last_snapshot;
    uint32_t snapshot_count;
} probe_telemetry_t;

probe_telemetry_t *probe_telemetry_new(const char *output_dir, uint64_t interval);
void               probe_telemetry_free(probe_telemetry_t *tm);

// Called every iteration. Logs to CSV and triggers snapshot if interval elapsed.
void probe_telemetry_record(probe_telemetry_t  *tm,
                            const probe_tree_t *tree,
                            uint64_t            iteration,
                            node_id_t           leaf,
                            seed_id_t           seed,
                            double              reward,
                            uint32_t            k);

// SIGUSR1 handler: dump current tree state immediately.
void probe_telemetry_signal_dump(probe_telemetry_t  *tm,
                                 const probe_tree_t *tree);
```

The visualizer in `tools/tree-visualizer/` is a standalone HTML/JS app that reads snapshot JSON files and renders tree structure with collapsible nodes, color-coded Q/N values, and a coverage-growth timeline. Build it in M3; debugging without it is excruciating.

---

## 5. Adaptive Rollout Budget `k`

`k` is not a static hyperparameter. It adapts based on the selected node's current statistics, balancing exploration density (small `k`, more tree updates) against rollout depth (large `k`, deeper exploration per update).

Adaptation rule, applied at the start of each rollout for the selected node:

```
if N(node) < 10:
    k = k_min                              # cold node: collect diverse signals fast
elif Q_variance(node) > variance_threshold:
    k = min(k_max, k_min * 2^log2(N(node)/10))   # high-variance promising node: explore deeper
else:
    k = k_min * 2                          # stable, less interesting: medium batch
```

`Q_variance` is computed online via Welford's method (the rollout manager maintains a running variance per node). `variance_threshold` defaults to a fraction (e.g., 0.25) of the global mean reward variance.

This adaptation does not violate I4 (no prediction). It uses only observed past statistics to allocate present effort; it does not extrapolate that future reward will follow past distribution. The rule is deterministic and reactive.

Defaults: `k_min = 32`, `k_max = 1024`. Tune empirically in M3.

---

## 6. Cold Start

For the first `cold_start_budget` executions of a campaign (default 10,000), the tree exists and is updated, but selection bypasses UCT and uses AFL++'s native scheduler (`cull_queue` plus the existing energy assignment). After the cold-start window, UCT takes over selection.

This is not a learned warm-up. It is a deterministic phase boundary: AFL++'s hand-tuned scheduler is a known-reasonable heuristic for the early phase when the tree has insufficient statistics, and using it during cold start is a static design choice, not a prediction.

The tree is built throughout cold start (every execution updates abstract state and visit counts), so by the time UCT activates, the tree already has meaningful structure rooted in the initial corpus exploration.

---

## 7. Milestones

### Milestone 1: AFL++ Baseline and Build Integration (Week 1)

**Goal**: Buildable PROBE fork with all `#ifdef PROBE_ENABLED` blocks present but inactive; baseline AFL++ behavior preserved when PROBE is compiled out.

**Tasks**:

1. Fork AFL++ at a recent stable commit. Record commit hash in `docs/upstream.md`.
2. Add the project layout from Section 3, with empty stub implementations of all PROBE source files.
3. Wire the build system: `PROBE_BUILD=1` adds the new sources and defines `PROBE_ENABLED`. Without it, AFL++ builds and runs unchanged.
4. Run a 6-hour campaign with `PROBE_BUILD=0` on `libpng_read_fuzzer` from FuzzBench. Document baseline results in `docs/baseline_results.md`.
5. Run a 6-hour campaign with `PROBE_BUILD=1` but with all PROBE logic stubbed (i.e., calls into `probe_*` functions return immediately without effect). Verify no behavioral regression.

**Validation**:

- V1.1: `make` builds cleanly with and without `PROBE_BUILD`.
- V1.2: With `PROBE_BUILD=0`, 6-hour `libpng_read_fuzzer` campaign covers within 5% of published vanilla AFL++ FuzzBench number on equivalent hardware.
- V1.3: With `PROBE_BUILD=1` and stubs only, exec/s degrades by less than 2% relative to V1.2.
- V1.4: Same seed reproduces same first-1000-execution coverage trajectory across both build modes.

**Deliverable**: A buildable fork with verified parity to upstream AFL++.

---

### Milestone 2: Abstraction Pilot (Week 2-3)

**Goal**: Empirically validate that frontier-weighted LSH produces tree-friendly abstract state distributions across diverse targets. This is the highest-risk milestone.

**Tasks**:

1. Implement `probe-abstraction.c` per Section 4.2.
2. Implement a minimal harness that runs AFL++ with PROBE_ENABLED, computes abstract state for each execution, and logs `(execution_count, distinct_states_seen)` to CSV every 1000 executions. The tree itself is not yet active; this milestone is purely about abstraction behavior.
3. Run 6-hour campaigns on at least 5 diverse FuzzBench targets:
   - `libpng_read_fuzzer` (image, structured)
   - `libxml2_xml_read_memory_fuzzer` (XML parsing)
   - `re2_fuzzer` (regex, deeply branched)
   - `bloaty_fuzz_target` (binary parsing)
   - `sqlite3_ossfuzz` (text-based query language)
4. For each target, sweep at least 4 LSH parameter configurations:
   - `(n_hashes=4, proj_dim=8, frontier_weight=1.0)`  baseline, no frontier weighting
   - `(n_hashes=4, proj_dim=8, frontier_weight=4.0)`  light frontier emphasis
   - `(n_hashes=8, proj_dim=16, frontier_weight=4.0)`  recommended default
   - `(n_hashes=16, proj_dim=32, frontier_weight=4.0)`  fine-grained
5. Plot abstract-state-count over time for each (target, config) combination. Save to `docs/figures/m2_*.png`.
6. Profile abstraction overhead per call. Document in `docs/abstraction_tuning.md`.

**Validation**:

- V2.1: For at least one configuration per target, the abstract state count at 6 hours is within `[200, 5000]`. Both extremes are failure modes.
- V2.2: For the recommended default config, the growth curve is sub-linear (concave) on at least 4 of 5 targets. Use a simple test: state count at 3 hours should be at least 60% of state count at 6 hours.
- V2.3: Two runs with identical seeds produce identical state ID sequences for the first 10,000 executions.
- V2.4: Per-call overhead under 50 microseconds at the recommended default config.

**Failure Mode**: If V2.1 or V2.2 fails for the recommended default, do not proceed to M3. Document the failure and switch to Phase 2 hierarchical abstraction (Section 4.2). This is a research bottleneck, not an engineering speed-bump; treat it as such.

**Deliverable**: Working abstraction with empirically-validated default parameters and documented per-target recommendations.

---

### Milestone 3: Tree, UCT, and End-to-End Integration (Week 4-6)

**Goal**: Functional PROBE that selects via UCT, runs adaptive rollouts, and at minimum matches vanilla AFL++ performance.

**Tasks**:

1. Implement `probe-tree.c` (Section 4.1) including unit tests in `tests/unit/test_tree.c`. Coverage target 80%+ on `probe-tree.c`.
2. Implement `probe-rollout.c` (Section 4.3) with adaptive `k` (Section 5).
3. Modify `afl-fuzz-one.c` to integrate PROBE:
   - During cold start, call AFL++'s native scheduler.
   - After cold start, call `probe_tree_select` to choose the seed.
   - Replace the havoc batch with a call to `probe_rollout_run`.
   - After rollout, call `probe_tree_backprop`.
4. Implement `probe-telemetry.c` (Section 4.4).
5. Build the tree visualizer in `tools/tree-visualizer/`. It must support: tree structure with collapsible nodes, per-node `Q/N` and visit count, coverage-growth timeline overlay, snapshot replay (load multiple snapshots and step through them).
6. Run 6-hour campaigns on the same 5 targets from M2.

**Validation**:

- V3.1: Build clean with no warnings under `-Wall -Wextra -Werror`.
- V3.2: Unit test coverage for `probe-tree.c` exceeds 80%; tree invariants (no orphan nodes, depth bounded by visit history, value sum monotonic non-decreasing) tested via property-based tests.
- V3.3: 6-hour campaigns on all 5 targets cover within ±5% of vanilla AFL++. **PROBE must not regress.** If it does, profile and fix; do not proceed.
- V3.4: exec/s within 10% of vanilla AFL++ across all 5 targets (Invariant I1).
- V3.5: Tree visualizer renders snapshots correctly; tree node count after 6 hours is under 5,000 across all targets.
- V3.6: Reproducibility: same seed produces identical iteration log for the first 1,000 iterations across two runs.

**Critical Checkpoint**: This is the make-or-break milestone. PROBE here has no learning, no prior, no fancy mechanisms. If it cannot match vanilla AFL++ with pure UCT, then either the tree-search formulation does not provide benefit on these targets (a research finding worth documenting), or the implementation has overhead bottlenecks (most likely: abstraction call cost, rollout manager overhead, or telemetry I/O on the hot path). Profile and diagnose before proceeding.

**Deliverable**: Working PROBE binary, all five targets passing parity check, visualizer functional.

---

### Milestone 4: Full Evaluation (Week 7-9)

**Goal**: Production-quality evaluation against state-of-the-art baselines on standard and adversarial benchmarks.

**Tasks**:

1. Construct adversarial program suite in `data/adversarial/`. At least 5 synthetic programs designed to expose online-learning fuzzer failure modes:
   - **Deep magic gates**: 3+ nested branches each requiring a specific 4-byte magic constant.
   - **Late frontier shifts**: programs whose interesting region only opens after a specific input prefix is discovered, simulating mid-campaign regime change.
   - **Combinatorial gates**: branches requiring multiple havoc operators to combine in a specific sequence.
   - **Sparse reward zones**: large code regions with very low natural reward density adjacent to small high-reward regions.
   - **Distractor regions**: large code regions that absorb significant exploration budget without producing meaningful crashes (designed to mislead bandit-based prioritization).
   Document each program's design intent in `data/adversarial/README.md`.

2. Set up comparative evaluation:
   - **Baselines**: vanilla AFL++, MOPT, EcoFuzz, xFUZZ.
   - **Targets**: full FuzzBench standard suite plus the adversarial suite.
   - **Trials**: 5 runs per (fuzzer, target) pair, each 24 hours, on identical hardware with isolated CPU cores.
   - **Metrics**: cumulative edges covered, unique bugs found (cross-referenced against ground truth where available), time to first crash, exec/s.

3. Statistical analysis:
   - Mann-Whitney U test for pairwise coverage comparison.
   - Vargha-Delaney A12 effect size.
   - Per-target and aggregate plots.

4. Write `docs/evaluation.md` with all tables, plots, and statistical analyses.

**Validation**:

- V4.1: PROBE achieves no worse than parity with the best baseline on standard FuzzBench (no statistically significant regression at p<0.05).
- V4.2: On the adversarial suite, PROBE shows clear improvement over baselines, with effect size (A12) above 0.7 on at least 3 of the 5 adversarial programs.
- V4.3: Complete evaluation reproducible via `scripts/reproduce_paper.sh` from a fresh clone.

**Note on V4.1**: The original PROBE thesis is that pure tree search is the right formulation, not that it dominates everywhere. If standard FuzzBench shows parity rather than dominance, that is consistent with the thesis: standard targets do not exhibit the failure modes that motivate the tree-search formulation. The adversarial suite is where the thesis is tested. Frame the paper accordingly.

**Deliverable**: Complete evaluation results ready for paper submission to ICSE/ISSTA/USENIX Security.

---

## 8. Open Research Questions (Documented, Not Resolved)

These are questions PROBE does not attempt to answer in V1. Each is a candidate for follow-up work.

### 8.1 Hierarchical Abstraction

If M2's flat LSH abstraction is insufficient on some targets, investigate depth-dependent abstraction granularity. Coarser at root, finer near leaves. The principled motivation is that the tree's information needs change with depth: root-level decisions concern broad coverage regions, leaf-level decisions concern frontier subtleties. Implementation would extend `probe_abstraction_t` with a depth parameter and select projection dimension dynamically.

### 8.2 Tree Depth Management

For very long campaigns (24+ hours), tree depth may grow large enough to make selection traversal a non-trivial cost. Possible mitigations: depth-limited tree with deep-node merging, importance-sampled selection that skips intermediate levels, or partitioning the tree into a forest of shallow trees keyed by coverage region.

### 8.3 Rollout Independence

UCT's regret bound technically requires i.i.d. rollouts. AFL++ havoc rollouts violate this assumption due to internal scheduling state. The paper should discuss this gap honestly. A theoretically cleaner alternative is to derive PROBE's regret bound from adversarial bandit theory (EXP3 family), which assumes nothing about rollout independence at the cost of looser bounds.

### 8.4 Delayed Credit Assignment

A new edge discovery in rollout `t` may be credit to mutation chains that began in earlier rollouts. PROBE backpropagates only to the current rollout's path, which is a known approximation. Reward smoothing via an exponential moving average on per-seed reward is a possible mitigation; document as future work.

### 8.5 Multi-Worker Concurrency

V1 PROBE is single-threaded. AFL++ supports parallel fuzzing with multiple workers sharing a corpus. Naive extension: per-worker independent trees with periodic seed exchange via the shared corpus directory (the existing AFL++ mechanism). More sophisticated: shared tree with lock-free updates. Defer to V2.

---

## 9. Configuration

A single TOML file `probe.toml` controls runtime behavior:

```toml
[fuzzer]
target_binary = "/path/to/target"
corpus_dir = "/path/to/corpus"
output_dir = "/path/to/findings"
seed = 42

[tree]
puct_c = 1.4142135623730951    # sqrt(2), standard UCT default
initial_node_capacity = 1024

[abstraction]
type = "frontier_lsh"
n_hashes = 8
proj_dim = 16
frontier_weight = 4.0
covered_weight = 1.0

[rollout]
k_min = 32
k_max = 1024
variance_threshold = 0.25
cold_start_budget = 10000

[telemetry]
snapshot_interval_secs = 600
iter_log = true
log_level = "info"
```

---

## 10. Testing and Observability

### 10.1 Test Layers

- **Unit tests** (`tests/unit/`): tree mutations (expand, select, backprop), abstraction determinism, adaptive `k` rule. Property-based testing via lightweight C testing framework.
- **Integration tests** (`tests/integration/`): 60-second campaigns on tiny fixtures, verifying tree non-empty, no crashes, and reproducibility under fixed seeds.
- **Performance regression tests**: microbenchmarks on hot paths (tree selection, abstraction, backprop), checked into CI with a 15% regression threshold.

### 10.2 Required Telemetry

- Per-iteration CSV log: `iteration, leaf_node_id, seed_id, k, reward, exec_per_sec`.
- Periodic JSON tree snapshots every 10 minutes. Schema in `docs/snapshot_schema.md`.
- SIGUSR1 handler dumps current tree state on demand.

### 10.3 Visualizer

A standalone web app (`tools/tree-visualizer/`) reads snapshot JSON and renders:

- Tree structure with collapsible subtrees.
- Per-node `Q`, `N`, depth, attached seed count.
- Coverage growth timeline with overlays for tree expansion events.
- Comparison mode: load multiple snapshots and step through them as a timeline.

This tool is mandatory by M3, not optional. Debugging emergent tree-search behavior without visualization is impractical.

---

## 11. Performance Budget

| Component                         | Target (per call) | Hard Limit |
|-----------------------------------|-------------------|------------|
| Abstraction (LSH hash)            | < 30 microseconds | 50 microseconds |
| Tree selection (root-to-leaf)     | < 100 microseconds | 200 microseconds |
| Tree backprop (path update)       | < 50 microseconds | 100 microseconds |
| Telemetry record (no snapshot)    | < 5 microseconds  | 10 microseconds |
| Total scheduler overhead per rollout batch | < 1% | < 5% |
| Overall exec/s vs. vanilla AFL++  | within 5%         | within 10% |

Breach of any hard limit halts development. Profile with `perf` and AFL++'s built-in `AFL_DEBUG=1` instrumentation.

---

## 12. Anti-Patterns

Mistakes the agent might be tempted to make. Don't.

- **Adding a learned prior to "speed up cold start"**. The cold-start budget plus AFL++'s native scheduler handles this. A learned prior reintroduces the prediction problem PROBE is built to avoid.
- **Adding a sliding window over reward "to handle non-stationarity"**. UCB inherently handles this through the exploration term. Adding a window assumes recent past is more predictive of future than distant past, which is exactly the assumption PROBE rejects.
- **Pruning stagnant subtrees "to save budget"**. UCB's exploit term naturally decays as `Q/N` ratio dilutes. Pruning encodes a prediction that stagnation persists, violating I4.
- **Adjusting validation thresholds to make milestones pass**. Failing validation is information about the system, not a bureaucratic obstacle.
- **Inlining telemetry on the hot path**. Telemetry I/O must be deferred or async; never block fuzzing iterations on disk writes.
- **Over-engineering the abstraction in M2**. Start with the simplest LSH that meets validation. Hierarchical abstraction (Section 8.1) is a fallback if and only if the simple version fails.
- **Replacing AFL++ havoc with custom mutation logic**. Out of scope for PROBE V1. Havoc is the rollout engine; do not touch it.

---

## 13. Quick Start

```bash
# Clone and build
git clone <fork-of-AFLplusplus> probe-aflpp
cd probe-aflpp
PROBE_BUILD=1 make

# Run a campaign
./scripts/run_campaign.sh \
    --target ./targets/libpng_read_fuzzer \
    --corpus ./data/corpora/libpng \
    --duration 6h \
    --output ./findings/run_001

# Live tree visualization
cd tools/tree-visualizer
python -m http.server 8080
# open http://localhost:8080 and load ./findings/run_001/snapshots/

# Trigger immediate snapshot dump from running fuzzer
kill -USR1 $(pgrep -f probe-fuzz)

# Reproduce full paper evaluation
./scripts/reproduce_paper.sh
```

---

## 14. Definition of Done

Implementation is complete when:

1. All four milestones pass their validation criteria without threshold adjustment.
2. Build produces no warnings under `-Wall -Wextra -Werror`.
3. Unit test coverage for `probe-tree.c` and `probe-abstraction.c` exceeds 80%.
4. Tree visualizer is functional and documented.
5. `docs/` contains: upstream pin, design notes, baseline results, abstraction tuning guide, evaluation results, snapshot schema, and a reproducibility script that runs the entire evaluation end-to-end on a fresh machine.
6. The full evaluation completes successfully via `scripts/reproduce_paper.sh`.

---

End of specification.
