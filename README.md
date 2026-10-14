# `authopsy`

a simple tool exploring Linux authentication logs through data processing and security analysis, identifying failed login attempts, detecting suspicious activity, and uncovering patterns in authentication events.

```text
authopsy/
├── data/       # sample authentication logs
├── src/        # log processing
└── tests/      # automated tests
```

### `> current capabilities`

- parse authentication logs and extract structured fields
- identify and aggregate failed login attempts by source IP
- detect suspicious login patterns, including multiple usernames per IP and high login failure counts
- validate log entries and report malformed records
- configure detection thresholds through command-line arguments
- run automated tests for log parsing

### `> stack`

`python` · `linux` · `git`

### `> roadmap`

- [X] refactor log parsing into reusable functions
- [X] handle malformed log entries
- [X] add configurable detection thresholds
- [X] add automated tests for log parsing
- [ ] store structured events in PostgreSQL
- [ ] design a relational schema for authentication events
- [ ] automate log ingestion
- [ ] analyze temporal patterns in login attempts
- [ ] visualize authentication activity
- [ ] explore anomaly detection techniques

---

<sub>currently under development. sample data is synthetic.</sub>
