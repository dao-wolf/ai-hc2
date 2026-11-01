#!/bin/sh
# Install the git hooks that run the privacy gate: pre-commit scans the staged
# files and the commit identity, and commit-msg scans the commit message.
# Run it with `make hooks`. It never overwrites a hook it did not write.
set -eu

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

install_hook pre-commit "--check-identity --staged"
install_hook commit-msg '--message "$1"'
exit "$failed"
