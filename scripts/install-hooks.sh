#!/bin/sh
# Install a pre-commit hook that runs the privacy gate.
# Run it with `make hooks`. It never overwrites a hook it did not write.
set -eu

marker="installed by scripts/install-hooks.sh"
hook=$(git rev-parse --git-path hooks/pre-commit)

if [ -f "$hook" ] && ! grep -q "$marker" "$hook"; then
  echo "A different pre-commit hook already exists: $hook" >&2
  echo "Add this line to it yourself: python3 scripts/privacy_gate.py --check-identity" >&2
  exit 1
fi

mkdir -p "$(dirname "$hook")"
cat > "$hook" <<'HOOK'
#!/bin/sh
# AI HC2 pre-commit hook, installed by scripts/install-hooks.sh
exec python3 "$(git rev-parse --show-toplevel)/scripts/privacy_gate.py" --check-identity
HOOK
chmod +x "$hook"
echo "Installed the privacy-gate pre-commit hook."
