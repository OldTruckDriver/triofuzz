#!/bin/bash -ex
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -u

# Wrap cmake to add -DCMAKE_POLICY_VERSION_MINIMUM=3.5 for compatibility
# with older CMakeLists.txt (e.g., libjpeg-turbo 3.0.x branch)
# Create a cmake wrapper script
cat > /tmp/cmake << 'EOF'
#!/bin/bash
# Find the real cmake binary (skip our wrapper in the search)
REAL_CMAKE=""
IFS=':' read -ra PATHS <<< "$PATH"
for p in "${PATHS[@]}"; do
    if [ "$p" != "/tmp" ] && [ -x "$p/cmake" ]; then
        REAL_CMAKE="$p/cmake"
        break
    fi
done

# If this is a configuration call (not --build, --version, etc.), add the policy flag
if [ "$1" != "--build" ] && [ "$1" != "--version" ] && [ "$1" != "--help" ] && [ "$1" != "-E" ]; then
    exec "$REAL_CMAKE" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 "$@"
else
    exec "$REAL_CMAKE" "$@"
fi
EOF
chmod +x /tmp/cmake
# Prepend to PATH so our wrapper is used
export PATH="/tmp:$PATH"

cat fuzz/branches.txt | while read branch; do
    pushd libjpeg-turbo.$branch
    if [ "$branch" = "main" ]; then
        sh fuzz/build.sh
    else
        sh fuzz/build.sh _$branch
    fi
    popd
done
