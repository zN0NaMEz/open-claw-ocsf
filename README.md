# open-claw-ocsf — LLM Privacy Gateway for OCSF security logs

Sanitizes security logs so they can be sent to a language model, and turns
the model's answer back into real values. Format-preserving encryption (FF3-1)
hides each value; a PostgreSQL ledger of issued tokens means a token the model
invented is refused rather than decrypted into something plausible.

## ⚠️ Do not run this on production logs yet

**There is no anti-prompt-injection layer.** A sanitized document still carries
attacker-controlled free text — `finding_info.desc`, `unmapped.*` values,
process names — straight into a model prompt. Tokenization hides *identities*;
it does nothing about *instructions* hidden in log content.

Until that layer exists, use synthetic or otherwise controlled test data only.

Two further temporary pieces, both deliberate and both flagged in code:

- **Desktop/server and privileged-user classification is a heuristic**
  (`PC-` / `SRV-` hostname prefixes, a hardcoded username list). It prints a
  warning on every run. Replace it with an asset inventory and an IAM lookup
  before production.
- **Malware family names are not redacted.** `Trojan.Generic` stays readable
  because it is threat intelligence rather than CII. Revisit separately.

## Layout

| Path | What |
| --- | --- |
| `ver_1/encryp.ipynb` | The system: Stage 3, Stage 2, Stage 1, the gateway, Stage 0 + the file pipeline |
| `ver_1/test_encryp.ipynb` | Its 176 tests |
| `Data/` | Log corpus and pipeline output (git-ignored) |

Cells are separated by tag. In `encryp.ipynb` the five cells tagged `library`
are the whole system, in dependency order. `test_encryp.ipynb` executes
exactly those cells, holds the pytest module in cells tagged `test`, and ends
with a `runner` cell that stitches them together and runs real pytest — open
it and Run All, or call `run_tests("-k", "...")`.

## Pipeline

```
Data/ocsf_edr_mock.ndjson   OCSF, one document per line
        │
        ├─ Stage 0  validate_ocsf       shape checks before anything trusts it
        ├─ Stage 1  classify_and_mark   HOST_DESKTOP / USER_PRIV / FILE_PATH_* / AGENT
        ├─ Stage 2  mark_cii            field rules + free-text sweep
        ├─ Stage 3  tokenize_log        FF3 over suffixes + issued ledger
        ▼
Data/ocsf_sanitized.log     one JSON document per line, LLM-ready
```

The corpus is already OCSF, so there is no parsing stage: one line is one
document. `run_pipeline(limit=N)` caps a run while iterating; the
10,000-record mock takes about 8 seconds and produces 18.9 MB.

The decrypt side (`detokenize_log`, `unmark_cii`, `restore_from_llm`) lives in
`encryp.ipynb`. A validator and a model client are not built yet.

## Environment

| Variable | Purpose |
| --- | --- |
| `FF3_KEY` / `FF3_TWEAK` | A single key, named by `FF3_KEY_VERSION` (default `v1`) |
| `FF3_KEY_<V>` / `FF3_TWEAK_<V>` | One pair per version, for a key ring |
| `FF3_ACTIVE_KEY_VERSION` | Which version encrypts new tokens |
| `DATABASE_URL` | psycopg connection string |

Use a **14-hex-character (56-bit) tweak**: that selects FF3-1, the revision
NIST kept after the attacks on the original FF3. A 16-character tweak selects
the original FF3.

```bash
pip install ff3 "psycopg[binary]" pytest
```

`psycopg` is imported lazily, so everything except `connect_database()` works
without it installed.

## The ledger

The vault is what makes a sanitized log reversible: without a record that a
token was issued, `safe_decrypt` refuses it, so an in-memory stand-in turns
every run into a one-way trip.

| Backend | Use |
| --- | --- |
| `connect_database()` | Postgres, via `DATABASE_URL`. What production uses. |
| `SqliteLedger()` | One file under `Data/`. Durable, but one writer, no roles, no network. |

Both take the same place in `run_pipeline(conn=...)` — the engine needs no
change, only a different connection. To stand Postgres up:

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=x --name vault postgres:16
export DATABASE_URL=postgresql://postgres:x@localhost:5432/postgres
python -c "import ...; ensure_schema(connect_database())"
```

## Design notes

- **Vaultless.** The ledger stores `token`, `prefix`, `suffix_len` and
  `key_version` — never a plaintext. A database breach alone reveals nothing;
  it takes the FF3 key too. The flip side is that losing the key loses the
  data, so key backup matters as much as database backup.
- **Tokens are global and deterministic.** The same host is the same token
  everywhere, which is what lets a model correlate — and equally what lets two
  datasets be linked. There is no per-case or per-tenant separation.
- **Key rotation is additive.** Each token records the key version that
  encrypted it; the ring keeps every version that can still decrypt.
  `key_versions_in_use(conn)` says when an old key can be retired.
- **Small value domains are enumerable.** Anyone who can call the sanitizer
  can build a lookup table without ever seeing the key. Access to the gateway
  is the real control.
- **The prefix is cleartext**, so the *category* of a value is visible by
  design — an analyst can still see "one internal host reached three external
  addresses".
- `actor` in the audit log is recorded, not authenticated.
- **A host's kind comes from the record first.** `device.type`, then
  `device.type_id`, and only then a guess from the hostname prefix. Just that
  last step is a heuristic, and only it warns.
