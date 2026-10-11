# `log-analyzer`

<p align="center">
  <samp>parsing logs, finding patterns.</samp>
</p>

a small python project exploring linux authentication logs through data processing and security analysis.

```text
log-analysis/
├── data/       # sample authentication logs
├── src/        # log processing
└── tests/      # automated tests
```

### `> current capabilities`

- parse authentication log entries
- identify failed login attempts
- aggregate events by source IP

### `> stack`

`python` · `linux` · `git`

### `> roadmap`

- [X] identify failed authentication attempts
- [X] divide failed attempts by source IP
- [X] handle malformed log entries
- [X] extract structured fields from log entries
- [ ] detect suspicious login patterns
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
