#!/bin/sh
# What the image actually contains, printed rather than remembered.
#
# A scanner reports the *source* package: Docker Scout names
# `pkg:deb/debian/perl` for CVE-2026-82560, and Debian's `perl` source produces
# `perl-base` — Essential, which dpkg itself depends on and which cannot be
# removed — as well as `perl`, which can. Which of them is installed decides
# whether that finding is ours to close or only ours to record, and that is a
# question about the image and not about the Dockerfile.
#
# Run by .github/workflows/docker-build-check.yml, which builds and publishes
# nothing:
#     docker run --rm -i --entrypoint sh patchradar:build-check - < inspect.sh
set -eu

echo "── perl packages installed ──"
dpkg-query -W -f '${Package} ${Version} essential=${Essential} priority=${Priority}\n' \
    'perl*' 'libperl*' 2>/dev/null || echo "  none"

echo
echo "── what depends on them ──"
for pkg in perl perl-base perl-modules-5.40 libperl5.40; do
    if dpkg-query -W "$pkg" >/dev/null 2>&1; then
        echo "  $pkg is needed by:"
        apt-cache rdepends --installed "$pkg" 2>/dev/null | tail -n +3 | sed 's/^/    /' || true
    fi
done

echo
echo "── build tooling, which the Dockerfile removes ──"
for pkg in pip setuptools wheel; do
    if python -c "import importlib.metadata as m, sys; sys.stdout.write(m.version('$pkg'))" \
        2>/dev/null; then
        echo "  <- $pkg is STILL PRESENT"
    else
        echo "  $pkg absent, as intended"
    fi
done

echo
echo "── size of the installed set ──"
printf '  %s packages\n' "$(dpkg-query -f '.\n' -W | wc -l)"
