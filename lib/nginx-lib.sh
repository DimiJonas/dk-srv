# shellcheck shell=bash
# Installing nginx files safely – shared by nginx/install-nginx.sh (dk-srv's own sites) and the
# apps' ops/root/install.sh. Installed by install.sh to /usr/local/lib/dk-srv/nginx-lib.sh.
#
#   . /usr/local/lib/dk-srv/nginx-lib.sh
#   plan_file DEST SRC            install SRC as DEST (root, 644) if different
#   plan_link NAME                sites-enabled/NAME -> sites-available/NAME
#   plan_unlink NAME              remove sites-enabled/NAME
#   plan_remove PATH              remove a file (e.g. an old name)
#   nginx_apply [--diff]          show what changes; install it all, check (nginx -t), reload –
#                                 or, if nginx doesn't accept it, put EVERYTHING back as it was
# Every changed path is noted for the file integrity check (/var/lib/dk-srv/aide-expected).
: "${NGINX_DIR:=/etc/nginx}"
: "${DK_STATE:=/var/lib/dk-srv}"
NGINX_AVAILABLE="$NGINX_DIR/sites-available"
NGINX_ENABLED="$NGINX_DIR/sites-enabled"
_files_dest=() _files_src=() _links_add=() _links_del=() _removes=()
plan_file() { _files_dest+=("$1"); _files_src+=("$2"); }
plan_link() { _links_add+=("$1"); }
plan_unlink() { [ -e "$NGINX_ENABLED/$1" ] || [ -L "$NGINX_ENABLED/$1" ] && _links_del+=("$1"); return 0; }
plan_remove() { [ -e "$1" ] && _removes+=("$1"); return 0; }

nginx_apply() {
  local only_diff=no changes=0 i dest src l old work
  [ "${1:-}" = --diff ] && only_diff=yes
  # a server without IPv6: nginx can't open [::] addresses – leave those lines out
  if [ ! -e /proc/net/if_inet6 ]; then
    for src in "${_files_src[@]}"; do sed -i -E '/^[[:space:]]*listen[[:space:]]+\[::\]/d' "$src"; done
  fi
  local changed=() todo_add=()
  for i in "${!_files_dest[@]}"; do
    dest=${_files_dest[$i]} src=${_files_src[$i]}
    if [ -e "$dest" ] && cmp -s "$src" "$dest"; then
      echo "== $dest: no change"
    else
      echo "== $dest: changes (- now, + new)"
      if [ -e "$dest" ]; then diff -u "$dest" "$src" 2>/dev/null | tail -n +3 || true; else echo "   (new file)"; fi
      changed+=("$i"); changes=$((changes + 1))
    fi
  done
  for l in "${_links_add[@]}"; do
    [ "$(readlink "$NGINX_ENABLED/$l" 2>/dev/null)" = "$NGINX_AVAILABLE/$l" ] && continue
    echo "== switch on: $NGINX_ENABLED/$l -> $NGINX_AVAILABLE/$l"; todo_add+=("$l"); changes=$((changes + 1))
  done
  for l in "${_links_del[@]}"; do echo "== switch off: $NGINX_ENABLED/$l (the file in sites-available stays)"; changes=$((changes + 1)); done
  for l in "${_removes[@]}"; do echo "== remove (old name): $l"; changes=$((changes + 1)); done
  if [ "$changes" -eq 0 ]; then echo "== nginx: nothing to change"; return 0; fi
  [ "$only_diff" = yes ] && return 0

  work=$(mktemp -d)
  local undo=()   # commands that restore the old state, run in reverse order if nginx -t fails
  for i in "${changed[@]}"; do
    dest=${_files_dest[$i]}
    if [ -e "$dest" ]; then cp -p "$dest" "$work/$i"; undo+=("cp -p '$work/$i' '$dest'"); else undo+=("rm -f '$dest'"); fi
    install -d -m 755 "$(dirname "$dest")"
    install -o root -g root -m 644 "${_files_src[$i]}" "$dest"
  done
  for l in "${todo_add[@]}"; do
    old=$(readlink "$NGINX_ENABLED/$l" 2>/dev/null || true)
    if [ -n "$old" ]; then undo+=("ln -sfn '$old' '$NGINX_ENABLED/$l'"); else undo+=("rm -f '$NGINX_ENABLED/$l'"); fi
    ln -sfn "$NGINX_AVAILABLE/$l" "$NGINX_ENABLED/$l"
  done
  for l in "${_links_del[@]}"; do
    if [ -L "$NGINX_ENABLED/$l" ]; then undo+=("ln -sfn '$(readlink "$NGINX_ENABLED/$l")' '$NGINX_ENABLED/$l'")
    else cp -p "$NGINX_ENABLED/$l" "$work/link-$l"; undo+=("cp -p '$work/link-$l' '$NGINX_ENABLED/$l'"); fi
    rm -f "$NGINX_ENABLED/$l"
  done
  i=0
  for l in "${_removes[@]}"; do i=$((i + 1)); cp -p "$l" "$work/rm-$i"; undo+=("cp -p '$work/rm-$i' '$l'"); rm -f "$l"; done
  # (for the file integrity check: these changes are expected)
  if [ -d "$DK_STATE" ]; then
    { for i in "${changed[@]}"; do echo "${_files_dest[$i]}"; done
      for l in "${todo_add[@]}" "${_links_del[@]}"; do echo "$NGINX_ENABLED/$l"; done
      printf '%s\n' "${_removes[@]}"; } | grep . >> "$DK_STATE/aide-expected" || true
  fi
  if ! nginx -t 2>"$work/test.log"; then
    cat "$work/test.log" >&2
    for (( i=${#undo[@]}-1; i>=0; i-- )); do eval "${undo[$i]}"; done
    rm -rf "$work"
    echo "nginx doesn't accept the new config – everything is back as it was, nothing changed." >&2
    return 1
  fi
  rm -rf "$work"
  if systemctl is-active --quiet nginx 2>/dev/null; then systemctl reload nginx; echo "== installed, nginx reloaded"; else echo "== installed (nginx isn't running)"; fi
}
