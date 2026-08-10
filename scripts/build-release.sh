#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH" >&2
  exit 2
fi

version="${tag#v}"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$project_root/dist"
build_dir="$dist_dir/build"

rm -rf "$dist_dir"
mkdir -p "$build_dir"

platforms=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

for platform in "${platforms[@]}"; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  archive_base="wheredns_${version}_${goos}_${goarch}"
  stage="$build_dir/$archive_base"
  executable="wheredns"
  if [[ "$goos" == "windows" ]]; then
    executable="wheredns.exe"
  fi

  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X github.com/MinottiAlessandro/WhereDNS/internal/cli.Version=$version" \
      -o "$stage/$executable" ./cmd/wheredns
  cp LICENSE README.md "$stage/"

  if [[ "$goos" == "windows" ]]; then
    (cd "$stage" && zip -q "$dist_dir/$archive_base.zip" "$executable" LICENSE README.md)
  else
    tar -C "$stage" -czf "$dist_dir/$archive_base.tar.gz" "$executable" LICENSE README.md
  fi
done

(cd "$dist_dir" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS)
rm -rf "$build_dir"
echo "Release archives written to $dist_dir"
