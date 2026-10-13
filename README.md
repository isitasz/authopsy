# `authopsy`

a simple tool exploring Linux authentication logs through data processing and security analysis, identifying failed login attempts, detecting suspicious activity, and uncovering patterns in authentication events.

```text
log-analyzer/
├── data/       # sample authentication logs
├── src/        # log processing
└── tests/      # automated tests
```

### `> current capabilities`

- parse authentication log entries
- identify failed login attempts
- aggregate events by source IP
- handle malformed log entries
- extract structured fields from log entries
- detect suspicious login patterns

### `> stack`

`python` · `linux` · `git`

### `> roadmap`

- [ ] add configurable detection thresholds
- [ ] add automated tests
- [ ] refactor log parsing into reusable functions
- [ ] store structured events in PostgreSQL
- [ ] design a relational schema for authentication events
- [ ] automate log ingestion
- [ ] analyze temporal patterns in login attempts
- [ ] visualize authentication activity
- [ ] explore anomaly detection techniques

---

<sub>currently under development. sample data is synthetic.</sub>
