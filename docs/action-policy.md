# Action classification policy

Lucy classifies structured action types before approval, budget reservation, or
execution. The classifier is deterministic and does not inspect model-authored
justifications.

Known read-only operations may be allowed, known side effects require human
approval, and intrinsically privileged operations are denied. Unknown action
types are denied by default. In particular, model requests cannot decide an
approval, raise a budget, mutate archive/audit history, run a shell, or issue raw
database operations.

Classification returns the applicable budget account, but reservation and
settlement remain a separate durable control step. No classifier result itself
executes an action.
