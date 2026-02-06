#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

# export http_proxy=http://127.0.0.1:7892
# export https_proxy=http://127.0.0.1:7892

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

export WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

pushd "$TARGET/freetype2"
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc) clean
make -j$(nproc)
make install

mkdir -p "$WORK/poppler"
cd "$WORK/poppler"
rm -rf *

EXTRA=""
test -n "$AR" && EXTRA="$EXTRA -DCMAKE_AR=$AR"
test -n "$RANLIB" && EXTRA="$EXTRA -DCMAKE_RANLIB=$RANLIB"

# Save original CFLAGS/CXXFLAGS/LDFLAGS/LIBS for later use
SAVED_CFLAGS="$CFLAGS"
SAVED_CXXFLAGS="$CXXFLAGS"
SAVED_LDFLAGS="$LDFLAGS"
SAVED_LIBS="$LIBS"

# Temporarily clear all compiler/linker flags during CMake configuration
# CMake's detection tests need clean flags to work properly
# We'll set the flags after configuration for the build phase
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS
unset LIBS

# Set compiler if CC/CXX are defined
CMAKE_CC_FLAG=""
CMAKE_CXX_FLAG=""
test -n "$CC" && CMAKE_CC_FLAG="-DCMAKE_C_COMPILER=$CC"
test -n "$CXX" && CMAKE_CXX_FLAG="-DCMAKE_CXX_COMPILER=$CXX"

# Configure CMake without sanitizer flags
# Explicitly set empty flags to ensure CMake uses clean flags for detection tests
cmake "$TARGET/repo" \
  $EXTRA \
  $CMAKE_CC_FLAG \
  $CMAKE_CXX_FLAG \
  -DCMAKE_BUILD_TYPE=debug \
  -DCMAKE_C_FLAGS="" \
  -DCMAKE_CXX_FLAGS="" \
  -DCMAKE_C_FLAGS_INIT="" \
  -DCMAKE_CXX_FLAGS_INIT="" \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DBUILD_GTK_TESTS=OFF \
  -DBUILD_QT5_TESTS=OFF \
  -DBUILD_CPP_TESTS=OFF \
  -DENABLE_LIBPNG=ON \
  -DENABLE_LIBTIFF=ON \
  -DENABLE_LIBJPEG=ON \
  -DENABLE_SPLASH=ON \
  -DENABLE_UTILS=ON \
  -DWITH_Cairo=ON \
  -DENABLE_CMS=none \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_GLIB=OFF \
  -DENABLE_GOBJECT_INTROSPECTION=OFF \
  -DENABLE_QT5=OFF \
  -DENABLE_LIBCURL=OFF \
  -DWITH_NSS3=OFF \
  -DFREETYPE_INCLUDE_DIRS="$WORK/include/freetype2" \
  -DFREETYPE_LIBRARY="$WORK/lib/libfreetype.a" \
  -DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so"

# Now set the flags for the build phase using cmake -D to modify cache
# This sets flags only for building, not for configuration tests
if [ -n "$SAVED_CFLAGS" ]; then
  cmake . -DCMAKE_C_FLAGS="$SAVED_CFLAGS"
fi
if [ -n "$SAVED_CXXFLAGS" ]; then
  cmake . -DCMAKE_CXX_FLAGS="$SAVED_CXXFLAGS"
fi

# Set linker flags for tool programs (pdfimages, pdftoppm)
# These tools need magma.o (for magma_log) but should NOT link collabfuzz/triofuzz (has main() conflict)
SAVED_LIBS_ORIG="$SAVED_LIBS"
# Remove -lcollabfuzz and -ltriofuzz but keep all other libraries (like -l:magma.o)
LIBS_WITHOUT_COLLABFUZZ=$(echo "$SAVED_LIBS" | sed 's/-lcollabfuzz\b//g' | sed 's/-ltriofuzz\b//g' | sed 's/  */ /g' | sed 's/^ *//;s/ *$//')
if [ -n "$LIBS_WITHOUT_COLLABFUZZ" ]; then
  # Set CMAKE_EXE_LINKER_FLAGS so CMake uses these flags when linking executables
  cmake . -DCMAKE_EXE_LINKER_FLAGS="$SAVED_LDFLAGS $LIBS_WITHOUT_COLLABFUZZ"
fi

# Restore environment variables for make (CMake will use its cache, but some build systems may check env)
export CFLAGS="$SAVED_CFLAGS"
export CXXFLAGS="$SAVED_CXXFLAGS"
export LDFLAGS="$SAVED_LDFLAGS"
export LIBS="$LIBS_WITHOUT_COLLABFUZZ"

make -j$(nproc) poppler poppler-cpp pdfimages pdftoppm
EXTRA=""

cp "$WORK/poppler/utils/"{pdfimages,pdftoppm} "$OUT/"

# Restore LIBS for building the fuzzer (which needs to link against collabfuzz)
export LIBS="$SAVED_LIBS_ORIG"

$CXX $CXXFLAGS -std=c++11 -I"$WORK/poppler/cpp" -I"$TARGET/repo/cpp" \
    "$TARGET/src/pdf_fuzzer.cc" -o "$OUT/pdf_fuzzer" \
    "$WORK/poppler/cpp/libpoppler-cpp.a" "$WORK/poppler/libpoppler.a" \
    "$WORK/lib/libfreetype.a" $LDFLAGS $LIBS -ljpeg -lz \
    -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread


unset http_proxy
unset https_proxy