#!/bin/bash
set -e

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$TARGET/repo"
./autogen.sh
./configure --disable-shared --enable-ossfuzzers
make -j$(nproc) clean
make -j$(nproc) ossfuzz/sndfile_fuzzer

# Re-link the fuzzer with CollabFuzz library
echo "[libsndfile] Re-linking fuzzer with CollabFuzz library..."

# Use the already compiled object file
OBJ_FILE="ossfuzz/sndfile_fuzzer-sndfile_fuzzer.o"
if [ ! -f "$OBJ_FILE" ]; then
    OBJ_FILE="ossfuzz/.libs/sndfile_fuzzer-sndfile_fuzzer.o"
fi

# Link with all required libraries
# Note: libcommon.a contains code that depends on external libraries
# We need to link against all external dependencies that libsndfile uses
# Some libraries like id3tag may be optional or provided by other libraries

# Build list of external libraries
# Note: id3tag functions are typically provided by libmp3lame, so we don't need -lid3tag
# Try linking without id3tag first
EXTERNAL_LIBS="-lFLAC -lvorbis -lvorbisenc -lopus -logg -lmpg123 -lmp3lame -lm"

# Try linking without id3tag (id3tag functions may be in libmp3lame)
if ! $CXX $CXXFLAGS -std=c++11 \
    "$OBJ_FILE" \
    -o "$OUT/sndfile_fuzzer" \
    src/.libs/libsndfile.a \
    src/GSM610/.libs/libgsm.a \
    src/G72x/.libs/libg72x.a \
    src/ALAC/.libs/libalac.a \
    src/.libs/libcommon.a \
    $LDFLAGS $LIBS \
    $EXTERNAL_LIBS 2>&1 | tee /tmp/libsndfile_link.log; then
    # If linking failed and error mentions id3tag, try with it
    if grep -q "undefined reference.*id3tag" /tmp/libsndfile_link.log 2>/dev/null; then
        echo "[libsndfile] id3tag symbols not found in libmp3lame, trying with -lid3tag..."
        EXTERNAL_LIBS="$EXTERNAL_LIBS -lid3tag"
        $CXX $CXXFLAGS -std=c++11 \
            "$OBJ_FILE" \
            -o "$OUT/sndfile_fuzzer" \
            src/.libs/libsndfile.a \
            src/GSM610/.libs/libgsm.a \
            src/G72x/.libs/libg72x.a \
            src/ALAC/.libs/libalac.a \
            src/.libs/libcommon.a \
            $LDFLAGS $LIBS \
            $EXTERNAL_LIBS
    else
        # If it's a different error, show it and fail
        cat /tmp/libsndfile_link.log
        exit 1
    fi
fi

echo "[libsndfile] Fuzzer built and linked successfully"