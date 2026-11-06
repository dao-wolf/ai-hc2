#!/bin/sh
# Install the git hooks that run the privacy gate: pre-commit scans the staged
# files and the commit identity, commit-msg scans the commit message, and
# pre-push scans every commit the push would send (the message, author, file
# names and added lines), including commits that never passed through
# pre-commit, such as a cherry-pick or a merge.
# Run it with `make hooks`. It never overwrites a hook it did not write.
#
# The hooks need your personal deny-list: with none, or an empty one, they stop
# the commit. If you have no deny-list, run `make hooks GENERIC_ONLY=1`. Those
# hooks check emails, home paths and secrets only, and say so on every commit.
set -eu

case "${1:-}" in
  "") flag="--require-denylist" ;;
  --generic-only) flag="--generic-only" ;;
  *)
    echo "usage: install-hooks.sh [--generic-only]" >&2
    exit 2
    ;;
esac

marker="installed by scripts/install-hooks.sh"
failed=0

# install_hook <hook name> <privacy gate arguments>
install_hook() {
  hook=$(git rev-parse --git-path "hooks/$1")
  if [ -f "$hook" ] && ! grep -q "$marker" "$hook"; then
    echo "A different $1 hook already exists: $hook" >&2
    echo "Add this line to it yourself: python3 scripts/privacy_gate.py $2" >&2
    failed=1
    return
  fi
  mkdir -p "$(dirname "$hook")"
  cat > "$hook" <<HOOK
#!/bin/sh
# AI HC2 $1 hook, $marker
exec python3 "\$(git rev-parse --show-toplevel)/scripts/privacy_gate.py" $2
HOOK
  chmod +x "$hook"
  echo "Installed the privacy-gate $1 hook."
}

install_hook pre-commit "--check-identity --staged $flag"
install_hook commit-msg "--message \"\$1\" $flag"
install_hook pre-push "--pre-push $flag"

if [ "$flag" = "--generic-only" ]; then
  echo "NOTICE: your personal deny-list is not checked by these hooks." >&2
else
  echo "These hooks stop a commit or a push when your deny-list is missing or empty."
  echo "With no deny-list, run: make hooks GENERIC_ONLY=1"
fi
exit "$failed"
