#!/usr/bin/env bash
# Outer goal loop: one `opencode run` per iteration, gated by an executable
# acceptance check. The goal and its progress live in GOAL.md / PROGRESS.md, so
# state survives compaction, crashes, and new sessions.
#
# Exit codes:
#   0  acceptance gate passed
#   1  setup or opencode failure
#   2  bad arguments
#   3  iteration limit reached
#   4  agent reported BLOCKED
#   5  no repository progress for two consecutive iterations
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_ITER=10
AGENT="goal-runner"
MODEL=""
CHECK="scripts/check.sh"
AUTO=1
COMMIT=0
DRY_RUN=0
LOG_DIR=".goal-loop"
SESSION_FILE="$LOG_DIR/session"

usage() {
  cat <<'EOF'
Usage: scripts/goal-loop.sh [options]

  -n, --max N        maximum iterations (default: 10)
  -a, --agent NAME   agent to run (default: goal-runner)
  -m, --model M      model override, provider/model[#variant]
  -c, --check PATH   acceptance script (default: scripts/check.sh)
      --no-auto      do not pass --auto to opencode run
      --commit       commit after each iteration (requires a clean tree)
      --dry-run      print the first prompt and exit
  -h, --help         show this help

The loop refuses to start unless GOAL.md contains `status: active`.
Logs and the session id live in .goal-loop/ (gitignored).
EOF
}

die() {
  echo "goal-loop: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--max)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      MAX_ITER="$2"
      shift 2
      ;;
    -a|--agent)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      AGENT="$2"
      shift 2
      ;;
    -m|--model)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      MODEL="$2"
      shift 2
      ;;
    -c|--check)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      CHECK="$2"
      shift 2
      ;;
    --no-auto)
      AUTO=0
      shift
      ;;
    --commit)
      COMMIT=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "goal-loop: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$MAX_ITER" =~ ^[1-9][0-9]*$ ]] || die "--max must be a positive integer"
command -v opencode >/dev/null 2>&1 || die "opencode is not on PATH"
[[ -f GOAL.md ]] || die "GOAL.md not found"
[[ -f scripts/goal-prompt.md ]] || die "scripts/goal-prompt.md not found"
[[ -x "$CHECK" || -f "$CHECK" ]] || die "acceptance command not found: $CHECK"

if ! grep -Eq '^status:[[:space:]]*active' GOAL.md; then
  die "GOAL.md is not active (set \`status: active\` after filling in the objective and acceptance list)"
fi

if [[ "$COMMIT" -eq 1 ]]; then
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "--commit requires a git repository"
  [[ -z "$(git status --porcelain)" ]] || die "--commit requires a clean tree at start"
fi

mkdir -p "$LOG_DIR"
if [[ -f "$SESSION_FILE" ]]; then
  SESSION="$(<"$SESSION_FILE")"
else
  SESSION="ses_goalloop$(date +%Y%m%d%H%M%S)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    printf '%s\n' "$SESSION" >"$SESSION_FILE"
  fi
fi

# Repository state excluding the append-only progress log, so that a loop which
# only rewrites PROGRESS.md counts as stalled.
tree_state() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git status --porcelain=v1 --untracked-files=normal -- . \
      ':(exclude)PROGRESS.md' ':(exclude).goal-loop' | cksum
  else
    find . -path ./.git -prune -o -path ./.goal-loop -prune -o -type f -print \
      | sort | cksum
  fi
}

commit_iteration() {
  local n="$1"
  if [[ "$COMMIT" -eq 1 ]]; then
    git add -A
    git commit -q -m "goal-loop: iteration $n" || echo "goal-loop: nothing to commit for iteration $n"
  fi
}

PROMPT_BASE="$(<scripts/goal-prompt.md)"
stalls=0
last_state="$(tree_state)"

for ((i = 1; i <= MAX_ITER; i++)); do
  stamp="$(date +%Y%m%d-%H%M%S)"
  log="$LOG_DIR/iter-$(printf '%03d' "$i")-$stamp.log"
  prompt="$(printf '%s\n\nIteration %d of %d. Session: %s.\nRun `scripts/check.sh` before reporting your status.\n' "$PROMPT_BASE" "$i" "$MAX_ITER" "$SESSION")"

  args=(run --session "$SESSION" --agent "$AGENT")
  if [[ -n "$MODEL" ]]; then
    args+=(--model "$MODEL")
  fi
  if [[ "$AUTO" -eq 1 ]]; then
    args+=(--auto)
  fi

  echo "== goal-loop: iteration $i/$MAX_ITER =="
  echo "   session: $SESSION"
  echo "   log:     $log"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '\n   opencode'
    printf ' %q' "${args[@]}"
    printf ' <prompt below>\n\n%s\n' "$prompt"
    exit 0
  fi

  set +e
  opencode "${args[@]}" "$prompt" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e

  status_line="$(grep -E '^STATUS: (DONE|CONTINUE|BLOCKED)' "$log" | tail -n 1 || true)"
  echo "   reported: ${status_line:-<none>}"

  if [[ -x "$CHECK" ]]; then
    if "$CHECK"; then
      echo "== goal-loop: acceptance gate passed after $i iteration(s) =="
      commit_iteration "$i"
      exit 0
    fi
  elif bash "$CHECK"; then
    echo "== goal-loop: acceptance gate passed after $i iteration(s) =="
    commit_iteration "$i"
    exit 0
  fi

  if [[ "$rc" -ne 0 && -z "$status_line" ]]; then
    die "opencode exited $rc without a STATUS line; see $log"
  fi

  case "$status_line" in
    *BLOCKED*)
      echo "== goal-loop: blocked — ${status_line#STATUS: BLOCKED} ==" >&2
      exit 4
      ;;
  esac

  now_state="$(tree_state)"
  if [[ "$now_state" == "$last_state" ]]; then
    stalls=$((stalls + 1))
    echo "   no repository change detected (stall $stalls/2)"
    if [[ "$stalls" -ge 2 ]]; then
      echo "== goal-loop: no progress for two iterations, stopping ==" >&2
      exit 5
    fi
  else
    stalls=0
  fi
  last_state="$now_state"

  commit_iteration "$i"
done

echo "== goal-loop: iteration limit ($MAX_ITER) reached without acceptance ==" >&2
exit 3
