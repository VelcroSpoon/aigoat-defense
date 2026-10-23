# Documentation

**Authors:** Christopher Aguilar Mendez, Simon Grondin and Jeremiah Kisamba Mwamba, Bishop's University AI Cybersecurity
Challenge 2026

Start here. The AI Goat Firewall documentation is organized by what you need to do, following the
[Diátaxis](https://diataxis.fr) framework: **how-to guides** to get a task done, **reference** to look
something up, and **explanation** to understand why.

New to the project? Read in this order: the [architecture document](ARCHITECTURE.md), then the
[code structure guide](CODE_STRUCTURE.md), then the [decision records](decisions/README.md).

## How-to guides (get a task done)

| Task | Where |
|---|---|
| Start and stop the app | [Root README](../README.md); from PowerShell: `& "C:\Program Files\Git\bin\bash.exe" scripts/start.sh` |
| Switch a firewall on or off | [Architecture §6.4](ARCHITECTURE.md#64-admin-flips-a-switch), or the admin page `/admin/kb-firewall` |
| Run the tests | [Code structure §6](CODE_STRUCTURE.md#6-tests) |
| Reproduce the numbers | `python -m eval.firewall.run_benchmark` and `python -m eval.kb_firewall.run_benchmark` |
| Run the three attacks from a terminal | `python -m eval.firewall.demo_attacks` |
| Add a KB cue, a language, a secret kind or a control | [Code structure §5](CODE_STRUCTURE.md#5-how-to-extend) |
| Record a design decision | [Decision log](decisions/README.md#how-to-add-one) |

## Reference (look it up)

| Document | Contents |
|---|---|
| [Action firewall](../docs/action-firewall.md) | Policy table, switches, results, limitations |
| [Leak firewall](../docs/leak-firewall.md) | What counts as a secret, encodings handled, switches, limitations |
| [Code structure](CODE_STRUCTURE.md) | Repository map, dependency rules, conventions, module sizes |
| [Guardrails in AI Goat](../docs/guardrails.md) | Every upstream guardrail and what it checks (upstream document) |
| `config/defense_profiles.yml` | Which controls run per surface and level |
| `config/config.yml` → `kb_firewall:` | KB firewall settings |

## Explanation (understand why)

| Document | Question it answers |
|---|---|
| [Architecture (arc42)](ARCHITECTURE.md) | How is the system structured, deployed and run; what are its risks? |
| [Architecture decisions](decisions/README.md) | Why enforce in code? Why noisy-OR? Why sentence-by-sentence streaming? |

## Upstream AI Goat documentation

Labs, workshops and the agentic Top 10 belong to the upstream project and are unchanged:
[labs](../docs/labs/), [workshop guide](../docs/workshop-guide.md), [workshop validation](../docs/workshop/),
[OWASP Agentic Top 10 notes](../docs/agenttop10/).

## Keeping docs current

- Change the docs in the same commit as the code they describe.
- Prefer a short, correct page over a long one; delete what is outdated.
- Numbers in the docs come from the benchmark scripts; re-run them when the rules change.
