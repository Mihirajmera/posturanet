# PosturaNet outcome-share receiver

The one hosted piece of PosturaNet (FR-45a, R9; decided 2026-11-24). When a customer turns on
`outcome_share`, `posturanet verify` sends one record per finished fix:

```json
{"control": "EC2.19", "fix_type": "sg_ingress", "outcome": "held", "evidence_days": 3, "agent_version": "0.5.1"}
```

[`api/outcomes.py`](api/outcomes.py) is the whole service. It is public so anyone can check what
it keeps:

- `POST /api/outcomes` accepts exactly those five fields (a test keeps them in step with
  `posturanet.outcome_share.SharedOutcome`) and refuses anything else with 400: extra fields,
  a control that isn't `SERVICE.N`, bodies over 1 KB. It adds one to a counter per
  `control | fix_type | outcome`, the evidence days to a sum, and one to the agent version's
  count. Nothing else is stored: no record, no time, no request headers, no IP address, and
  the handler writes no access log.
- `GET /api/outcomes` returns the counters: per control and fix type, how many fixes held, how
  many were reverted, and the mean evidence days. That is the "which fixes break production"
  dataset.

Known limit: the endpoint takes anonymous posts, so someone could inflate the counts. Counts
are a signal, not proof; nothing in PosturaNet acts on them automatically.

## Deploy (once, founder)

1. In Vercel, **Add New → Project**, import `Mihirajmera/posturanet`, set **Root Directory** to
   `receiver`, Framework Preset **Other**, and deploy. No build step; Vercel runs
   `api/outcomes.py` as a Python function.
2. In that project, **Storage → Marketplace → Upstash (Redis)**, create a free database and
   connect it to the project. That sets `KV_REST_API_URL` and `KV_REST_API_TOKEN`. Redeploy.
3. Optional: **Settings → Domains**, add `outcomes.posturanet.com` and the DNS record Vercel
   shows.
4. Check it: `curl https://<deployment>/api/outcomes` returns `{"schema": "posturanet.outcomes/v1", "rows": [], ...}`.

Then a customer opts in with:

```yaml
outcome_share:
  enabled: true
  endpoint: https://outcomes.posturanet.com/api/outcomes
```

and `posturanet outcomes preview run.json` shows exactly what would be sent.

## Tests

`tests/unit/test_receiver.py` in the core runs with the rest: `pytest -q`.
