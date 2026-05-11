# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email -- do not open public issues.

## Defensive use only

This project is a **defensive adversary-emulation harness** intended for blue-team training and detection-engineering. Its techniques are stubs that emit synthetic evidence into a sandboxed workdir; they do **not** perform real attacker actions. Specifically:

- No technique opens network sockets to attacker-controlled infrastructure.
- No technique modifies the real Windows registry, schedules real tasks, dumps real LSASS memory, or extracts real secrets.
- No technique writes outside the configured `workdir`; all paths flow through `Technique._safe_join`.
- A deny-list (`DENY_LIST`) rejects technique IDs associated with destructive impact (data destruction, ransomware, inhibit recovery, defacement, firmware corruption, disk wipe). Both the registry and the executor enforce this.
- The LLM planner is constrained to the registry's published IDs and is filtered against the deny-list before execution.

## Threat model

- The harness assumes operation on a developer or analyst workstation, possibly inside a CI sandbox.
- It does not protect against an operator who is determined to extend the framework to perform real-world attacker actions; that is outside the project's defensive scope. Removing the deny-list, re-implementing a technique stub to actually execute, or wiring the framework to a real C2 server is not supported and would require forking.
- The LLM advisor receives a description of the registry (technique IDs, names, descriptions) and the user-supplied objective. No personal data, evidence, or system state is transmitted.

## Reporting misuse

If you discover this project being used to coordinate real attacker activity, contact the repository owner. The project's name and README make its defensive purpose unambiguous.
