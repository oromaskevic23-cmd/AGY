Author & Architect: Alexander Romaskevich (RomaskevicH)

Production readiness checklist

Non-exhaustive gate criteria
- Architecture documented (yes)
- Specification: sufficiently complete to implement core primitives
- Reference implementation: verified against spec
- Multi-validator devnet: operational
- Public testnet: open and monitored
- Load and fault testing: completed with results
- Security review: formal third-party audit and response
- Release candidate: tested, hardened, and signed off
- Mainnet gate: activation plan, timelocks, and community readiness

Operational controls
- Monitoring, observability, and incident response
- Key management and rotation processes
- Backup and recovery plans

Mermaid — roadmap (simplified)
```mermaid
gantt
title AGY canonical roadmap
dateFormat  YYYY-MM-DD
section Roadmap
Architecture :done, a1, 2026-01-01, 30d
Specification :active, a2, after a1, 90d
Reference Implementation :a3, after a2, 120d
Local Devnet :a4, after a3, 30d
Multi-Validator Devnet :a5, after a4, 60d
Public Testnet :a6, after a5, 60d
Load Test :a7, after a6, 30d
Fault Test :a8, after a7, 30d
Security Review :a9, after a8, 30d
Release Candidate :a10, after a9, 30d
Mainnet Gate :a11, after a10, 30d
Mainnet :a12, after a11, 30d
```
