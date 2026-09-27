#!/bin/sh
# screenpipe — AI that knows everything you've seen, said, or heard
# https://screenpipe.com
# Install a published HC binary. Never opens or initializes a brain.
set -eu
main() {
  version=${HC_VERSION:-}
  install_dir=${HC_INSTALL_DIR:-"$HOME/.local/bin"}
  [ "$#" -eq 0 ] || { echo 'Use HC_VERSION=vX.Y.Z or HC_INSTALL_DIR=/path to configure installation.' >&2; return 1; }
  case "$install_dir" in /*) ;; *) echo 'HC_INSTALL_DIR must be absolute.' >&2; return 1;; esac
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64) target=aarch64-apple-darwin ;;
    Darwin:x86_64) target=x86_64-apple-darwin ;;
    Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    *) echo 'Unsupported platform. See the HC GitHub release downloads.' >&2; return 1 ;;
  esac
  command -v curl >/dev/null
  command -v tar >/dev/null
  if command -v sha256sum >/dev/null; then hash_tool=sha256sum
  elif command -v shasum >/dev/null; then hash_tool=shasum
  else echo 'Install sha256sum or shasum first.' >&2; return 1; fi
  repo=https://github.com/louis030195/hyperconsciousness
  if [ -z "$version" ]; then
    # Public releases exclude drafts; include alpha releases deliberately.
    releases=$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 30 https://api.github.com/repos/louis030195/hyperconsciousness/releases?per_page=1)
    version=$(printf '%s\n' "$releases" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  fi
  printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$' || { echo 'No valid published HC version found.' >&2; return 1; }
  stage=$(mktemp -d)
  pending=
  trap 'test -z "$pending" || rm -f "$pending"; rm -rf "$stage"' EXIT
  trap 'exit 130' INT TERM HUP
  archive="hc-$target.tar.gz"
  base="$repo/releases/download/$version"
  for name in "$archive" SHA256SUMS; do
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 180 "$base/$name" -o "$stage/$name"
  done
  expected=$(awk -v name="$archive" '$2 == name {print $1}' "$stage/SHA256SUMS")
  printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' || { echo 'Missing or ambiguous release checksum.' >&2; return 1; }
  if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$stage/$archive" | cut -d ' ' -f1)
  else actual=$(shasum -a 256 "$stage/$archive" | cut -d ' ' -f1); fi
  [ "$actual" = "$expected" ] || { echo 'HC checksum mismatch; nothing installed.' >&2; return 1; }
  members=$(tar -tzf "$stage/$archive" | LC_ALL=C sort)
  [ "$members" = "$(printf 'LICENSE\nhc')" ] || { echo 'Unexpected archive contents.' >&2; return 1; }
  tar -xzf "$stage/$archive" -C "$stage"
  [ -f "$stage/hc" ] && [ ! -L "$stage/hc" ] || { echo 'Invalid release binary.' >&2; return 1; }
  chmod 755 "$stage/hc"
  [ "$("$stage/hc" --version)" = "hc ${version#v}" ] || { echo 'HC binary version mismatch.' >&2; return 1; }
  mkdir -p "$install_dir"
  [ ! -L "$install_dir/hc" ] || { echo 'Existing hc is a symlink; choose HC_INSTALL_DIR explicitly.' >&2; return 1; }
  pending=$(mktemp "$install_dir/.hc-install.XXXXXX")
  cp "$stage/hc" "$pending"
  chmod 755 "$pending"
  mv -f "$pending" "$install_dir/hc"
  pending=
  # Version-pinned installations stay pinned unless explicitly opted in later.
  if [ "${HC_AUTO_UPDATE:-1}" != 0 ] && [ -z "${HC_VERSION:-}" ]; then
    pending=$(mktemp "$install_dir/.hc-update-enable.XXXXXX")
    printf '1\n' > "$pending"
    chmod 600 "$pending"
    mv -f "$pending" "$install_dir/.hc-auto-update"
    pending=
    printf 'Automatic updates enabled (background checks every six hours of use).\n'
  else
    rm -f "$install_dir/.hc-auto-update"
  fi
  printf 'Installed %s at %s/hc\n' "$version" "$install_dir"
  case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add to your shell PATH: export PATH="%s:$PATH"\n' "$install_dir";; esac
}
# A complete function is parsed before downloads or installation can begin.
main "$@"
