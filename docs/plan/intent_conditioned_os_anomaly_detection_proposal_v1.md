# From Intent to Effects: Calibrated OS-Level Anomaly Detection for AI Agents

**Research proposal — v1**  
**Project:** PICOT  
**Date:** 2026-09-03  
**Status:** Initial research plan and feasibility gate

## Executive summary

AI agents execute semantically diverse tasks through shells, coding tools, browsers, local applications, and external services. Existing operating-system security mechanisms can isolate or restrict an agent, but they generally do not know what authority is appropriate for the user's current request. Conversely, application-layer safety mechanisms can reason about the request but may not observe the complete process tree or the actual system effects produced by an agent and its tools.

This project proposes **Intent-Conditioned OS Anomaly Detection**: given a trusted user prompt and execution context, predict a distribution or calibrated prediction set over the OS-level effects that are reasonable for the task. At runtime, attribute a process tree to the agent session, abstract raw system events into semantic effects, and score observed behavior according to how consistent it is with the predicted task-conditioned behavior. The score can support a graduated response: allow expected effects, record low-risk deviations, request narrow additional authority for uncertain effects, and block high-risk effects that are strongly inconsistent with the task.

The core methodological hypothesis is that a pretrained language model can serve as a **data-efficient semantic prior** over expected system effects. The language model is not treated as a trusted policy oracle. Its predictions are grounded with environment information and verified-benign behavioral traces, then statistically calibrated on held-out executions. This hybrid design is intended to require much less local training data than a trace-only anomaly detector while being more accurate and environment-aware than a prompt-only LLM envelope.

The project begins with a strict feasibility gate: determine whether the correct user prompt provides measurable predictive information about benign OS behavior beyond the agent, harness, environment, tool inventory, and a generic behavioral profile. Correct-prompt predictions will be compared with prompt-shuffled controls at matched contract size and benign coverage. If aligned prompts do not consistently outperform shuffled prompts, the project will pivot away from intent-conditioned enforcement toward generic agent behavioral modeling or post-hoc anomaly explanation.

If the feasibility gate passes, the intended full-paper contributions are:

1. A formalization of intent-conditioned OS anomaly detection for AI agents.
2. A task-to-effect benchmark spanning multiple agent workload families, including but not limited to MCP.
3. A data-efficient hybrid predictor combining an LLM semantic prior, behavioral retrieval or learned profiles, and calibrated set prediction.
4. An evaluation of benign utility, excess authority, anomaly detection, calibration, and generalization to unseen task families, agents, tools, environments, and versions.
5. An end-to-end demonstration that calibrated predictions can be compiled into enforceable OS and network constraints.

## 1. Motivation

An agent's legitimate system behavior depends on its current task. Reading an SSH private key might be justified for a narrowly defined key-rotation task but highly anomalous for summarizing a CSV. Network access may be required to clone a repository but unjustified for editing a local document. A static per-agent sandbox must accommodate the union of all possible tasks and therefore becomes broad, while a conventional behavioral profile identifies what is common without determining what is authorized by the present request.

The missing link is a conditional model connecting application-layer intent to system-layer execution:

\[
P(\text{OS effects} \mid \text{prompt}, \text{agent}, \text{harness},
\text{environment}, \text{tools}, \text{history}).
\]

This is naturally framed as an anomaly-detection problem. Rather than asking only whether an event is globally unusual, the system asks whether it is unusual **for this task in this context**.

A pretrained LLM is attractive because it already contains broad procedural knowledge. It can often infer that compiling a Rust project is likely to invoke `cargo`, `rustc`, and a linker; that summarizing a local file should not normally require network egress; or that cloning a repository requires DNS, network access, Git, and filesystem writes. That semantic prior could substantially reduce the amount of local trace data required.

However, an LLM does not reliably know the exact installed paths, runtime dependencies, tool versions, temporary directories, organization-specific resources, or execution strategy selected by a particular agent. A prompt-only LLM is therefore a useful prior and baseline, but not a sufficiently trustworthy enforcement authority. Empirical grounding and calibration remain necessary.

## 2. Research objective

The primary objective is to determine whether application-layer intent can materially improve prediction and anomaly detection at the OS layer, and whether an LLM semantic prior can make this practical under limited-data conditions.

Let the execution context be

\[
x = (I, U, A, H, V),
\]

where:

- \(I\) is the user intent or task prompt;
- \(U\) is the user or organization profile;
- \(A\) is the executing agent and model;
- \(H\) is the harness, available tools, and current session history; and
- \(V\) is the environment, project, container image, and relevant software versions.

Let \(T\) be a raw execution trace and \(\phi(T)\) its abstraction into a set or graph of semantic system effects. The project will learn or approximate

\[
P(\phi(T) \mid x)
\]

and use it to produce both:

1. a pre-execution prediction set or **effect contract**; and
2. a runtime anomaly score for effects observed outside or near the boundary of that contract.

### 2.1 Primary research questions

**RQ1 — Value of intent.** Does conditioning on the correct prompt improve prediction of benign OS effects beyond agent-, harness-, user-, and environment-only profiles?

**RQ2 — Data efficiency.** How competitive is a zero-shot LLM semantic prior with a trace-trained anomaly detector, and how much verified local data is needed for a hybrid model to outperform either component alone?

**RQ3 — Calibration.** Can the predicted effect sets achieve a requested benign coverage level on held-out executions without granting excessive authority?

**RQ4 — Generalization.** How does performance change for unseen task families, agents, harnesses, tools, environments, and software versions?

**RQ5 — Security and utility.** At matched benign task success, do intent-conditioned contracts detect or contain more task-inconsistent and malicious effects than static sandboxes and unconditioned behavioral profiles?

**RQ6 — Adaptation.** Can a local user or organization profile improve accuracy without allowing compromised or anomalous behavior to become automatically normalized?

### 2.2 Central hypotheses

- **H1:** Correct-prompt conditioning predicts benign effects more accurately than shuffled-prompt and no-prompt controls at matched prediction-set size.
- **H2:** A hybrid LLM-plus-behavioral model achieves a better benign-coverage versus excess-authority frontier than prompt-only and data-only models.
- **H3:** Lightweight calibration substantially improves the reliability of LLM-derived effect scores without requiring large-scale model training.
- **H4:** Intent-conditioned anomaly scores separate benign and task-inconsistent effects under held-out task-family and agent/harness splits.
- **H5:** The hybrid reaches a target performance level with fewer verified task executions than a trace-only model.

## 3. Scope and non-goals

### 3.1 Initial scope

The initial paper will target Linux-based agent executions and three enforceable effect families:

1. **Filesystem:** read, write, create, delete, rename, and permission changes, including semantic path classes.
2. **Process:** program execution, relevant argument constraints, descendant creation, and privilege-sensitive operations.
3. **Network:** destination, port, protocol, direction, and a bounded representation of endpoint scope.

Credential access and persistence will be represented as high-risk semantic subclasses of these effects. Process attribution will use containers or cgroups so that descendants remain associated with the originating agent session.

The workload should include several families:

- shell and terminal tasks;
- coding-agent tasks;
- data-processing tasks;
- system-administration tasks;
- network retrieval and package-management tasks; and
- external tool and MCP tasks.

MCP is therefore an important evaluation stratum and a source of existing data, but not the definition of the problem.

### 3.2 Deferred scope

The following are valuable extensions but should not block the initial study:

- full browser-state and cloud-authority modeling;
- complete application-protocol or service-side mediation;
- deep IPC and shared-memory semantics;
- multi-agent delegation and cross-agent authority propagation;
- cryptographic tool manifests and remote attestation;
- universal support across operating systems; and
- complete causal attribution in shared-process environments.

### 3.3 Non-goals

- Proving that every anomalous effect is malicious.
- Predicting exact raw syscall sequences.
- Replacing deterministic sandboxing or access control with an LLM.
- Learning directly from every production execution without validation.
- Claiming a universal least-privilege policy independent of agent and environment.

## 4. From raw system calls to semantic effects

Raw syscall identity is insufficient for intent-aware security. Reading a project file and stealing a credential may both appear as `openat`; connecting to GitHub and connecting to an exfiltration endpoint both appear as `connect`. Common runtime calls such as `mmap`, `futex`, and shared-library reads can dominate traces while carrying little task-specific meaning.

PICOT will transform events into a resource- and argument-sensitive representation. A canonical effect record should contain fields such as:

```yaml
subject:
  session_id: string
  cgroup_id: string
  process_image: string
  parent_image: string

operation:
  family: file | process | network | ipc
  verb: read | write | create | delete | execute | connect

object:
  concrete_resource: string
  semantic_class: project_source | output | runtime | credential | system | external
  scope: exact | subtree | host | service | category

context:
  phase: setup | execution | verification | cleanup
  arguments: structured summary
  provenance: optional source labels
  timestamp: relative session time
```

The first prototype may use a bag or set of effects. A later version can add order, process-tree structure, and information-flow relationships to form an effect graph.

Runtime noise should be handled explicitly rather than hidden through broad policies. Effects may be categorized as:

- task-facing and scored;
- environment/runtime dependencies;
- permitted alternatives;
- sensitive or protected; and
- unsupported or unobserved.

## 5. Calibrated task-conditioned effect contracts

An effect contract is a structured prediction of what consequences are permitted for the current task. It is more expressive than a list of syscall names and may encode exact resources, scoped resource classes, alternative execution strategies, phases, budgets, and flow constraints.

For a task such as “Summarize the error logs in `/workspace/logs` and write `report.md`,” a simplified contract might be:

```yaml
files:
  read:
    - /workspace/logs/**
  write:
    - /workspace/report.md
    - /tmp/task-*/**
  protected:
    - ~/.ssh/**
    - ~/.aws/**
    - /etc/**

processes:
  alternatives:
    - [grep, awk]
    - [python3]
  descendants_must_remain_in_task_cgroup: true

network:
  allowed: false

persistence:
  allowed: false
```

### 5.1 Set-valued correctness

There may be multiple legitimate execution strategies. One agent may use Python, another `grep | awk`, and another a dedicated analysis tool. A single oracle trace is therefore not universal ground truth.

Each task should distinguish:

- effects required across valid solutions;
- permitted alternative effect groups;
- explicitly sensitive or forbidden effects;
- unscored runtime dependencies; and
- task and attack validators that determine the final outcome.

Static trace matching is diagnostic; successful execution under the contract is the final sufficiency test.

### 5.2 Calibration

For each candidate effect \(e\), a predictor produces a necessity or compatibility score

\[
q_\theta(e \mid x).
\]

A calibration procedure selects a threshold or set-construction rule using held-out verified-benign executions. For target error level \(\alpha\), the resulting prediction set \(C_\alpha(x)\) should approximately satisfy

\[
P(\phi(T_{\text{benign}}) \subseteq C_\alpha(x)) \geq 1-\alpha
\]

on the calibration distribution.

This is an empirical coverage statement, not a guarantee under arbitrary adversarial or distributional shift. The system must separately identify unfamiliar contexts and abstain when necessary.

Calibration can begin with a risk-controlling threshold selected to meet a target benign denial rate. A conformal-style extension can compute the maximum surprise of required effects in each calibration run and use an appropriate quantile to construct future prediction sets.

### 5.3 Runtime response

An observed trace can be assigned a risk-weighted anomaly score such as

\[
S(T,x) = \max_{e \in \phi(T)}
\left[ r(e)\left(1-q_\theta(e\mid x)\right) \right],
\]

where \(r(e)\) reflects the consequence of the effect. This supports graduated decisions:

- **Allow:** expected and covered by the contract.
- **Allow and record:** mildly unexpected but low risk.
- **Pause or request a narrow delta:** plausible but not confidently predicted.
- **Block:** high-risk and strongly inconsistent with the task.

Unexpected behavior should be described as a contract violation or anomaly, not automatically labeled malicious.

## 6. Proposed method

### 6.1 Semantic prior

A pretrained LLM receives trusted context available before execution:

- the user prompt;
- environment and project summary;
- available tools and commands;
- agent/harness identity;
- relevant resource namespaces; and
- the effect ontology and output schema.

It proposes abstract effects, alternatives, risk-sensitive exclusions, and ordinal confidence. It should not receive attack-side traces or untrusted runtime content during policy generation.

### 6.2 Environment grounding

A deterministic resolver maps abstract effects to concrete resources using:

- the current working directory;
- executable and package manifests;
- container image metadata;
- tool versions;
- mounted resources; and
- organization-specific path and endpoint mappings.

This keeps the LLM focused on semantic expectations rather than exact platform details it may hallucinate.

### 6.3 Behavioral retrieval and profiles

The system retrieves verified successful executions with similar prompts, task families, environments, and agent/harness configurations. It estimates effect frequency and variability at several levels:

```text
global agent behavior
  + organization/user profile
  + harness profile
  + task-family profile
  + environment/version profile
  + current prompt
```

The initial user profile should be a secondary personalization signal, not the primary boundary. A developer may legitimately perform many different activities, making an unconditional per-user profile too broad.

Profile updates must require trusted provenance, successful task validation, or explicit approval. Otherwise, repeated malicious behavior could gradually become normalized.

### 6.4 Fusion and calibration

For each candidate effect, a small model can combine:

- LLM inclusion and confidence;
- frequency in retrieved benign traces;
- prompt-to-task similarity;
- agent, harness, and environment match;
- resource existence and scope;
- version compatibility; and
- effect sensitivity.

Initial fusion models should be deliberately simple and auditable, such as logistic regression or gradient-boosted trees. Complex sequence or graph models should be introduced only if the simpler baselines reveal clear residual structure.

The output is then calibrated on a separate benign set and converted into an effect contract or abstention decision.

## 7. Data and benchmark plan

> **ACE scope correction (2026-09-03).** The initial text below treated the
> 1,979-session ACE-MCP subset as though it were the complete dataset. The
> canonical ACE corpus contains 4,047 sessions: 1,979 MCP sessions plus 2,068
> built-in-agent sessions spanning six delivery-vector families. The corrected
> reuse protocol and measured inventory are in
> [ace_intent_reuse_protocol_v1.md](ace_intent_reuse_protocol_v1.md). That
> protocol supersedes any conflicting collection assumptions in this v1
> proposal.

### 7.1 Existing assets

The current projects provide several useful starting points:

- ACE contains 4,047 sessions across 17 threat models and six delivery-vector families: 1,979 MCP-package-tampering sessions and 2,068 built-in-agent sessions. It includes synchronized syscall traces, tool snapshots, transcripts, and paired benign/malicious executions.
- PICOT includes 446 generated envelope contexts and enforcement evaluations. Its current results establish a useful baseline and expose the aligned-versus-misaligned specificity problem. See the [enforcement audit](../../experiments/enforcement/AUDIT_FINDINGS.md).
- ACE-XA adds a 592-session alternate-agent and alternate-scaffold evaluation corpus for later external validation.

These resources are sufficient for the initial feasibility study. New collection should be targeted only at gaps established by the ACE-derived experiment, particularly controlled authority-contrast tasks, semantic task-success validators, and additional repeated benign executions.

### 7.2 New data collection

Each benchmark task should include:

- a natural-language prompt;
- a controlled environment;
- agent, model, and harness metadata;
- a task success validator;
- multiple successful benign executions when possible;
- attributed OS telemetry;
- the abstract effect representation;
- protected and sensitive resource definitions; and
- optional paired task-inconsistent or malicious variants.

The independent sample is the task × environment/version × agent/harness configuration, not the individual syscall. Large event counts should not be treated as equivalent to a large number of independent training examples.

### 7.3 Dataset splits

Random session splits are insufficient because repeated executions and shared tools create leakage. The benchmark should include grouped splits for:

- unseen prompts within known task families;
- unseen task families;
- unseen agent models or harnesses;
- unseen tools or applications;
- unseen repositories or environments; and
- unseen software versions.

One split should intentionally preserve the agent and environment while changing only the prompt. This is necessary to isolate the incremental value of intent.

### 7.4 Data-efficiency study

The evaluation should vary the amount of local behavioral data available to the system:

- zero-shot LLM only;
- calibration only;
- a small number of verified examples per family;
- moderate local training data; and
- the full available trace-training set.

The desired result is that an LLM semantic prior plus lightweight calibration reaches a target security–utility operating point with materially fewer verified executions than a trace-only model.

## 8. Baselines

The minimum baseline suite is:

1. **Broad static sandbox:** conventional task-independent policy.
2. **Global behavioral profile:** common effects across all agent sessions.
3. **Per-user or organization profile:** historical effects for the identity.
4. **Per-agent/harness profile:** historical effects for the execution stack.
5. **Environment/tool profile:** context without the user prompt.
6. **Prompt-shuffled control:** full context with an incorrect prompt drawn from the same environment or task family.
7. **Prompt-only LLM:** zero-shot structured effect prediction.
8. **Behavioral retrieval:** effect sets from similar verified tasks.
9. **Data-trained conditional model:** prompt embeddings and execution context without an LLM policy prior.
10. **Hybrid model:** LLM prior plus behavioral/contextual grounding and calibration.
11. **Oracle/reference contract:** evaluation ceiling, not a deployable baseline.

Where appropriate, AuthBench-style file policy generation, ActPlane policies, and conventional anomaly detectors should be included as external comparisons.

## 9. Evaluation design

### 9.1 Benign sufficiency and tightness

- Task success rate under the predicted contract.
- Required-effect recall.
- Complete-session coverage.
- Contract size and risk-weighted authority surface.
- Unnecessary effect precision or overpermission.
- Escalation or approval frequency.

### 9.2 Anomaly detection and security

- AUROC and AUPRC for benign versus task-inconsistent traces.
- Detection by effect family and risk class.
- Attack success rate under enforcement.
- Fraction of high-risk unexpected effects blocked.
- Time to detection or intervention.
- False-block rate on benign successful executions.

### 9.3 Calibration

- Empirical coverage versus requested coverage.
- Coverage error by workload family.
- Prediction-set size at each target coverage.
- Risk–coverage and abstention–utility curves.
- Calibration under held-out environments and versions.

### 9.4 Generalization

- Cross-task-family performance.
- Cross-agent and cross-harness performance.
- Cross-tool/application performance.
- Cross-environment and cross-version performance.
- Performance with degraded or missing context.

### 9.5 Statistical protocol

- Split and bootstrap at the task/configuration level rather than the event level.
- Report confidence intervals and paired comparisons.
- Freeze the effect ontology and primary metrics before constructing adversarial variants.
- Report results per workload family in addition to pooled aggregates.
- Match contract size or benign coverage when comparing aligned and mismatched conditions.

## 10. Feasibility gate

The first decisive experiment should be completed before large-scale data collection or model training.

### 10.1 Inputs

Use successful benign episodes from the existing corpus and add a modest set of non-MCP terminal and coding tasks. For each episode, construct:

```text
prompt
agent/harness metadata
environment summary
abstract benign effect set
```

Initially restrict the effect representation to filesystem, process execution, network, credential access, and persistence.

### 10.2 Experimental conditions

Compare:

- global profile;
- agent/harness profile;
- environment profile without the prompt;
- correct-prompt LLM;
- prompt-shuffled LLM;
- behavioral retrieval;
- hybrid LLM plus retrieval/profile; and
- oracle/reference effects.

Shuffled prompts should be drawn from the same harness and environment or the closest possible matched context. This prevents the predictor from winning through unrelated environment differences.

### 10.3 Pass condition

The project proceeds as an intent-conditioned enforcement paper if:

- correct-prompt predictions consistently outperform prompt-shuffled predictions at matched size or benign coverage;
- the improvement is present across multiple workload families;
- it survives at least one held-out task-family or agent/harness split;
- hybrid prediction improves the benign-coverage versus authority frontier; and
- anomaly performance does not depend on obviously artificial sentinel paths or destinations.

The pass condition should be evaluated through confidence intervals and effect sizes rather than one arbitrary aggregate threshold.

### 10.4 Pivot condition

If correct and shuffled prompts remain effectively indistinguishable, the project should not claim that intent determines a useful enforcement boundary. Viable pivots include:

- generic agent/harness anomaly detection with prompts used for explanation;
- versioned application or tool behavioral profiles;
- an intent-to-effect benchmark documenting where semantic conditioning helps and fails; or
- post-hoc risk scoring rather than pre-execution blocking.

A rigorous negative result could still be scientifically useful if it establishes that system behavior is driven primarily by the execution stack rather than the natural-language task.

## 11. Enforcement architecture

Enforcement is downstream validation rather than the initial learning contribution.

The intended architecture is:

```text
trusted prompt and context
          |
          v
semantic prior + behavioral grounding
          |
          v
calibrated effect contract or abstention
          |
          v
filesystem/process/network enforcement
          |
          v
attributed runtime effects and anomaly updates
```

Practical components may include:

- containers or cgroups for attribution and descendant containment;
- Landlock, BPF-LSM, or ActPlane for filesystem and process restrictions;
- an egress proxy or network namespace for destination constraints;
- a credential broker for later high-value extensions; and
- explicit, narrow capability deltas when an execution encounters a legitimate unpredicted need.

The initial system should distinguish monitoring from prevention. Low-risk uncertain behavior can be recorded, while unexplained credential access, persistence, destructive system writes, or sensitive egress can be blocked or escalated.

## 12. Relationship to existing work

### AgentSight

AgentSight provides eBPF-based observability and post-hoc correlation between agent activity and system behavior. Its process observation is useful infrastructure, but the session-to-effect linking includes heuristic temporal and argument signals, followed by LLM interpretation. It does not learn a calibrated task-conditioned behavior distribution or enforce a pre-execution contract.

Paper: <https://arxiv.org/html/2508.02736>

### ActPlane

ActPlane provides an expressive OS-level policy DSL, process-tree-aware eBPF enforcement, temporal rules, and information-flow tracking. It also demonstrates policies generated from task descriptions. PICOT should not claim the first intent-derived OS policy or rebuild enforcement as its principal novelty. The distinction is prediction and calibration of a positive conditional behavior model, including sufficiency, excess authority, shuffled-intent controls, and OOD generalization. ActPlane is a potential backend and baseline.

Paper: <https://arxiv.org/html/2606.25189>

### AuthBench

AuthBench directly studies instruction plus environment to default-deny file read/write/execute policy generation over 120 tasks. It establishes that permission-boundary inference is difficult and that the minimal sufficient boundary depends on the executing agent. PICOT must therefore extend beyond “prompt to file allowlist.” The proposed distinction is a conditional distribution over broader OS effects, behavioral histories, data efficiency, anomaly scoring, calibration, and generalization.

Paper: <https://arxiv.org/html/2605.14859>  
Repository: <https://github.com/evolvent-ai/Authbench>

### ToolGuardian

ToolGuardian combines tool metadata, system traces, mock effects, and source analysis with task-aware declarative authorization. It is especially relevant to opaque external tools and effect composition. PICOT's intended contribution is broader agent behavior rather than an MCP-specific tool vetting system, with larger-scale conditional prediction, calibration, and OOD evaluation.

Paper: <https://arxiv.org/html/2607.21835>

### Task-conditioned least-privilege learning

Recent work trains a small agent model to prefer lower-authority actions using predefined multidimensional task envelopes. This crowds generic claims about learning least-privilege behavior but does not generate concrete resource-level contracts for opaque executions. PICOT instead predicts and enforces a task-conditioned effect boundary for an independently executing agent or tool.

Paper: <https://arxiv.org/html/2608.18351>

## 13. Publication strategy

### 13.1 ICLR-style contribution

For a machine-learning venue, the paper should emphasize:

- conditional structured or set prediction;
- LLMs as semantic priors over system behavior;
- data efficiency and learning curves;
- calibration, abstention, and selective prediction;
- task-, agent-, and environment-level distribution shift;
- a reusable benchmark; and
- the empirical value of application-layer intent for OS-level prediction.

The strongest result would show that the LLM-plus-calibration system reaches a given benign coverage and anomaly-detection operating point with substantially fewer verified traces than a data-only model.

### 13.2 Security-venue contribution

For USENIX Security, CCS, or NDSS, the paper would instead emphasize:

- an explicit adversary and trust model;
- process-tree attribution and complete mediation;
- containment of compromised or injected agents;
- profile poisoning and adaptive attacks;
- security–utility tradeoffs;
- enforceable contracts and capability refinement; and
- end-to-end system overhead.

The first version should choose one primary story rather than attempting to satisfy both venue styles equally. The recommended initial direction is the ICLR-style scientific question, with enforcement serving as validation.

## 14. Main risks and mitigations

### Risk 1: Intent adds little signal

The prompt may not predict low-level behavior beyond environment and harness context.

**Mitigation:** Run the correct-versus-shuffled prompt feasibility test first. Treat a negative answer as a pivot condition rather than hiding it.

### Risk 2: Raw behavior is too nondeterministic

Different agents and repeated runs may use different valid execution chains.

**Mitigation:** Predict semantic effects rather than exact syscall sequences; collect repeated executions; represent valid alternatives; use task completion as the final sufficiency test.

### Risk 3: LLM confidence is unreliable

Self-reported confidence should not be treated as probability.

**Mitigation:** Learn a separate calibration mapping using held-out benign traces and report empirical coverage.

### Risk 4: The behavioral profile becomes poisoned

Repeated malicious behavior could be incorporated as normal.

**Mitigation:** Update profiles only from trusted, validated, or explicitly approved executions. Maintain immutable protected-resource constraints.

### Risk 5: Evaluation rewards generic tightness

A restrictive but task-insensitive envelope may stop most attacks.

**Mitigation:** Use correct-versus-shuffled prompts, matched contract sizes, matched benign coverage, same-environment counterfactuals, and attacks inside otherwise plausible namespaces and destinations.

### Risk 6: Dataset scale is overstated

Thousands of syscall events or repeated sessions may represent few independent contexts.

**Mitigation:** Report the number of independent tasks, environments, versions, agents, and workload families. Split and bootstrap at those levels.

### Risk 7: Scope becomes unmanageable for one researcher

A universal policy across OS, browser, cloud, multi-agent, and service effects would require excessive engineering.

**Mitigation:** Restrict the initial contribution to Linux filesystem, process, and network effects; reuse existing attribution and enforcement components; defer cross-service and multi-agent authority.

## 15. Research phases and deliverables

### Phase 0 — Specification

Deliverables:

- frozen threat model and trust assumptions;
- effect ontology v1;
- trace-to-effect schema;
- benchmark unit and split definitions;
- primary metrics and pass/pivot criteria.

### Phase 1 — Feasibility study

Deliverables:

- normalized effect sets for an initial benign corpus;
- correct-prompt and prompt-shuffled LLM predictions;
- global, agent/harness, and environment profile baselines;
- matched-size and matched-coverage comparisons;
- a written go/no-go result.

### Phase 2 — Benchmark expansion

Deliverables:

- targeted authority-contrast tasks not already supported by ACE;
- repeat successful executions;
- task validators;
- protected-resource definitions;
- grouped OOD splits;
- paired task-inconsistent traces.

### Phase 3 — Hybrid prediction and calibration

Deliverables:

- behavioral retrieval baseline;
- data-only conditional predictor;
- LLM-plus-behavior fusion model;
- calibration and abstention module;
- data-efficiency and ablation studies.

### Phase 4 — Security and enforcement evaluation

Deliverables:

- contract compiler or backend integration;
- graded runtime response;
- task-completion and attack-containment evaluation;
- profile-poisoning and OOD stress tests;
- performance measurements.

### Phase 5 — Paper and artifact

Deliverables:

- frozen benchmark release;
- reproducible data-processing and evaluation pipeline;
- model prompts, checkpoints or weights where releasable;
- per-task results and statistical analysis;
- full paper centered on the selected venue story.

## 16. Immediate next actions

1. Freeze an effect ontology covering filesystem, process, network, credential, and persistence effects.
2. Convert a representative subset of existing benign traces into effect sets and measure repeat-run variability.
3. Define matched prompt-shuffling groups that preserve agent, harness, and environment context.
4. Generate zero-shot effect predictions for correct and shuffled prompts using a fixed prompt and output schema.
5. Implement global, per-agent/harness, environment-only, retrieval, and oracle baselines.
6. Evaluate intent value at matched contract size and matched benign coverage.
7. Decide whether to proceed, modify the effect abstraction, or pivot before expanding the corpus.

## 17. Success criteria for a full paper

The project is ready for a full-paper push when it can support the following claims with grouped OOD evaluation:

1. The correct task prompt contributes measurable predictive information about OS effects beyond non-intent context.
2. The hybrid model improves the benign-coverage versus admitted-authority frontier over LLM-only and data-only baselines.
3. Calibration produces reliable coverage and a useful abstention signal on held-out contexts.
4. Intent-conditioned anomaly scores improve detection or containment of task-inconsistent effects at matched benign utility.
5. The result holds across multiple workload families and is not specific to MCP, one agent, one tool, or synthetic sentinel resources.
6. The artifact permits independent reproduction of task-level splits, predictions, effect sets, and aggregate claims.

## 18. Working title and concise contribution statement

**Working title:** *From Intent to Effects: Calibrated OS-Level Anomaly Detection for AI Agents*

**Concise contribution statement:**

> We formulate intent-conditioned OS anomaly detection, construct a multi-workload task-to-effect benchmark, and show how a pretrained language model can provide a data-efficient semantic prior over expected agent behavior. By grounding that prior in verified execution profiles and calibrating structured effect prediction sets, the system seeks to preserve benign task completion while detecting or containing task-inconsistent system effects under agent, task, environment, and version shift.
