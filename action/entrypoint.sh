#!/usr/bin/env bash
# PosturaNet GitHub Action entrypoint. Inputs arrive as env vars, never interpolated into code.
set -uo pipefail

out="$(mktemp)"

# The commit a check run belongs to: the PR head, not the merge commit GitHub checks out.
head_sha() {
  python - <<'PY'
import json, os
sha = os.environ.get("GITHUB_SHA", "")
path = os.environ.get("GITHUB_EVENT_PATH", "")
if path and os.path.isfile(path):
    event = json.load(open(path, encoding="utf-8"))
    sha = (event.get("pull_request") or {}).get("head", {}).get("sha") or sha
print(sha)
PY
}

# Plan JSON for `check`, made with -lock=false so a check never takes the state lock.
make_plan() {
  local tf_root plan_bin
  tf_root="$(python -c 'from pathlib import Path; from posturanet.models.config import load_config; print(load_config(Path("."))[0].terraform.root)')" || return 1
  plan_bin="$(mktemp)"
  terraform -chdir="${tf_root}" init -input=false >&2 || return 1
  terraform -chdir="${tf_root}" plan -input=false -lock=false -out="${plan_bin}" >&2 || return 1
  terraform -chdir="${tf_root}" show -json "${plan_bin}" >"$1" || return 1
}

check_args=()
if [[ "${PN_CHECK_RUN}" == "true" ]]; then
  check_args=(--github-check --sha "$(head_sha)")
fi

case "${PN_COMMAND}" in
  fix)
    [[ -n "${PN_TARGET}" ]] || { echo "error: fix needs target" >&2; exit 2; }
    args=(fix "${PN_TARGET}" --repo . --format json)
    [[ "${PN_DRY_RUN}" == "true" ]] && args+=(--dry-run)
    [[ "${PN_OPEN_PR}" == "true" ]] && args+=(--open-pr)
    [[ -n "${PN_EVIDENCE}" ]] && args+=(--evidence-file "${PN_EVIDENCE}")
    ;;
  check)
    if [[ "${PN_SOURCE_ONLY}" == "true" ]]; then
      args=(contract check --source --repo . --format json "${check_args[@]}")
    else
      plan="${PN_PLAN}"
      if [[ -z "${plan}" ]]; then
        plan="$(mktemp --suffix .json)"
        if ! make_plan "${plan}"; then
          echo "error: terraform plan failed; PosturaNet can't check this change (UNKNOWN)" >&2
          echo "result=UNKNOWN" >>"${GITHUB_OUTPUT}"
          exit 3
        fi
      fi
      args=(contract check --plan "${plan}" --repo . --format json "${check_args[@]}")
    fi
    ;;
  contract-check)
    [[ -n "${PN_TARGET}" ]] || { echo "error: contract-check needs target (plan JSON)" >&2; exit 2; }
    args=(contract check --plan "${PN_TARGET}" --repo . --format json "${check_args[@]}")
    ;;
  *)
    echo "error: unknown command '${PN_COMMAND}' (use fix, check or contract-check)" >&2
    exit 2
    ;;
esac

posturanet "${args[@]}" >"${out}"
code=$?

python - "${out}" <<'PY' >>"${GITHUB_OUTPUT}"
import json, sys
try:
    doc = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    doc = {}
print(f"result={doc.get('result') or doc.get('status', '')}")
print(f"pr_url={doc.get('pr_url') or ''}")
print(f"check_url={doc.get('check_url') or ''}")
PY

# Human-readable summary on the job page.
posturanet_summary="$(python - "${out}" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(0)
if "stages" in doc:
    print(f"### PosturaNet · {doc['result']}\n")
    print(doc.get("result_detail", ""))
    for s in doc["stages"]:
        print(f"- **{s['name']}** {s['status']}: {s['summary']}")
else:
    print(f"### PosturaNet contract check\n\n{doc.get('summary', '')}\n")
    for r in doc.get("results", []):
        sym = {"PASS": "✓", "BLOCK": "✗"}.get(r["status"], "?")
        print(f"- {sym} `{r['address']}`")
        for reason in r.get("reasons", []):
            print(f"  - {reason}")
PY
)"
echo "${posturanet_summary}" >>"${GITHUB_STEP_SUMMARY}"

# UNKNOWN (exit 3) passes only when the workflow opted out of failing on it.
if [[ "${code}" == "3" && "${PN_COMMAND}" != "fix" && "${PN_FAIL_ON_UNKNOWN}" != "true" ]]; then
  exit 0
fi
exit "${code}"
