# Cloud Hermes Lucy working agreements

## Early-stage delivery default

Cloud Hermes Lucy is an early-stage venture. Prioritize proving the product and shipping useful functionality. Aim for roughly 3/10 rather than 8/10 initial security-assurance and quality effort. This expresses Ray's tolerance for an early product; it is not a measured security score or a claim that the product is secure.

- Build the smallest useful version and make ordinary implementation decisions autonomously within the authorized task.
- One agent may implement and finish a change. Do not create routine Lyra-Claude approval or review loops. Request independent review only when Ray asks or a concrete consequential issue warrants it.
- Verify the main user flow with the smallest relevant check. Run additional tests only to answer a specific consequential uncertainty or satisfy an existing enforced check.
- Do not repeatedly run broad suites, re-review unchanged work, or exhaustively test speculative edge cases.
- Accept rough edges, technical debt, and some edge-case failures while learning. Substantial rebuilding in roughly two months is acceptable if business evidence calls for it.
- Prefer simple architecture and basic security controls. Defer advanced hardening, elaborate recovery ceremonies, speculative scaling, and architectural polish until real usage or a concrete failure justifies them.
- Report briefly what works, what was actually checked, and significant known limitations. Do not turn every uncertainty into another gate or overstate product maturity.

This replaces the earlier default of extensive prelaunch assurance for early builds. It does not disable sandbox or permission controls, authorize unrelated actions, waive an explicit production or personal-data activation decision, or bypass an enforced CI, hook, hosting, or branch-protection check.

## Execution defaults

- For implementation requests, continue through clean in-scope steps to the useful finish line. Do not stop merely to ask whether to continue when the only useful answer would be "keep going."
- Preserve prior approvals within their stated scope. Ask one focused question only for a real authorization boundary, material unresolved design choice, consequential cost/scope change, or irreversible action.
- After two equivalent failures, change the diagnostic approach instead of repeating the same loop.
- Reuse still-valid verification evidence. After a fix, rerun the affected check rather than every previously passing suite unless the change has wider impact.
- Treat architecture, acceptance, and security documents as product constraints and historical evidence, not as standing instructions to perform every documented ceremony for every change.
