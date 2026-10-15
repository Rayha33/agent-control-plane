# Supervised worker admission

ACP can optionally limit new supervised worker launches when the shared host
already has too many retained worker slots in the same ACP database or too
little currently available memory. Both controls are opt-in and belong under `[supervisor]`:

```toml
[supervisor]
max_active_workers = 3
min_available_memory_bytes = 2147483648 # 2 GiB
```

`max_active_workers` accepts 1–65,535. The count includes every attempt whose
worker identity is retained in the database: launch reservations (`pid = -1`),
registered workers, and workers whose termination or cleanup is still
ambiguous. This conservative count is shared by supervisor processes using the
same ACP SQLite database; it is not a machine-wide registry across independent
ACP databases. SQLite serializes the final admission check and
reservation in one write transaction, immediately before a worker process can
start. Each reservation records the exact admission settings that authorized it;
supervisors sharing the database fail closed if their settings differ while any
worker slot is retained. Change these settings only after retained slots reach
zero. Reservations created by older ACP versions have no policy identity and
therefore block new launches until those workers and ambiguous reservations
clear. The preflight check also rejects an already-full host before updating the
attempt heartbeat. With no retained legacy slots, omitting both controls
preserves the existing unlimited behavior.

`min_available_memory_bytes`, when set, is checked using Linux
`/proc/meminfo`'s `MemAvailable` value. ACP reads at most 64 KiB without
following a symlink, requires exactly one well-formed `MemAvailable` record,
and accepts a sample no more than five seconds old or one second in the future.
Other operating systems, missing or malformed data, and stale samples refuse a
new launch while this policy is enabled. Without a memory floor, an unavailable
memory sample does not block a launch. The status view reports the configured
limits, retained-slot count, whether a policy conflict blocks launches, sample
source/time/value, and most recent refusal reason; the audit log records each
refused launch.

These controls provide backpressure, not a memory reservation or an OOM
prevention guarantee. `MemAvailable` is a kernel estimate of host-wide
reclaimable capacity, not the worker's future peak usage and not a cgroup-aware
limit. Host load can change after sampling, a worker can allocate more memory
than expected, and unmanaged processes or provider-native subagents are outside
ACP's counter. The cap and memory floor are independent safeguards: choose
explicit values for the deployment rather than deriving concurrency from CPU
count. ACP never terminates existing workers to satisfy a new launch limit.
Ambiguous worker identities continue to consume a slot until existing cleanup
logic has exact evidence to release them.
