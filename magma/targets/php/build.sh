#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

cd "$TARGET/repo"
export ONIG_CFLAGS="-I$PWD/oniguruma/src"
export ONIG_LIBS="-L$PWD/oniguruma/src/.libs -l:libonig.a"

# PHP's zend_function union is incompatible with the object-size sanitizer
export EXTRA_CFLAGS="$CFLAGS -fno-sanitize=object-size"
export EXTRA_CXXFLAGS="$CXXFLAGS -fno-sanitize=object-size"

# Save LDFLAGS and LIBS for later use in make
SAVED_LDFLAGS="$LDFLAGS"
SAVED_LIBS="$LIBS"

# Extract libraries needed for sapi/cli/php (magma.o but not collabfuzz)
# sapi/cli/php needs magma_log but has its own main(), so it shouldn't link collabfuzz
LIBS_FOR_CLI=$(echo "$SAVED_LIBS" | sed 's/-lcollabfuzz\b//g' | sed 's/  */ /g' | sed 's/^ *//;s/ *$//')

# Clear CFLAGS, CXXFLAGS, LDFLAGS, and LIBS during configure
# Configure scripts test the compiler with these flags, and they may fail
# if libraries (like -lcollabfuzz or -l:magma.o) don't exist yet or flags are incompatible
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS
unset LIBS

#build the php library
./buildconf
# LIB_FUZZING_ENGINE is used as FUZZING_LIB in the fuzzer link command
# We need to set it to the actual libraries (magma.o and collabfuzz)
# But we can't use $SAVED_LIBS during configure because it contains -lcollabfuzz
# which doesn't exist yet. So we set it to a placeholder first, then update it after configure.
LIB_FUZZING_ENGINE="-Wall" ./configure \
    --disable-all \
    --enable-option-checking=fatal \
    --enable-fuzzer \
    --enable-exif \
    --enable-phar \
    --enable-intl \
    --enable-mbstring \
    --without-pcre-jit \
    --disable-phpdbg \
    --disable-cgi \
    --with-pic

# Restore LDFLAGS and LIBS for make
export LDFLAGS="$SAVED_LDFLAGS"
export LIBS="$SAVED_LIBS"

# Update Makefile variables for linking
# EXTRA_LIBS is used by sapi/cli/php - needs magma.o but NOT collabfuzz (has own main)
# FUZZING_LIB is used by fuzzer - needs both magma.o AND collabfuzz (provides main)
# Use := for immediate expansion to prevent Make from parsing library names as targets
# Also escape $ signs in the library strings to prevent Make variable expansion
# IMPORTANT: We must preserve existing EXTRA_LIBS (which includes MBSTRING_SHARED_LIBADD with oniguruma)
# Also ensure oniguruma library is included for mbstring extension
if [ -f Makefile ]; then
    TMP_MAKEFILE=$(mktemp)
    # Escape $ signs in library strings ($$ becomes $ in Makefile)
    CLI_LIBS_ESCAPED=$(echo "$SAVED_LDFLAGS $LIBS_FOR_CLI" | sed 's/\$/$$$$/g')
    FUZZER_LIBS_ESCAPED=$(echo "$SAVED_LDFLAGS $SAVED_LIBS" | sed 's/\$/$$$$/g')
    # Escape oniguruma library path for Makefile
    ONIG_LIBS_ESCAPED=$(echo "$ONIG_LIBS" | sed 's/\$/$$$$/g')
    
    # Try to extract INTL_SHARED_LIBADD from Makefile
    INTL_LIBS_VALUE=$(grep "^INTL_SHARED_LIBADD[ :=]" Makefile | head -1 | sed -E 's/^INTL_SHARED_LIBADD[ :=]+//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || echo "")
    # If not found in Makefile, try to get ICU libraries from pkg-config
    if [ -z "$INTL_LIBS_VALUE" ] && command -v pkg-config >/dev/null 2>&1; then
        if pkg-config --exists icu-uc icu-io icu-i18n 2>/dev/null; then
            INTL_LIBS_VALUE=$(pkg-config --libs icu-uc icu-io icu-i18n 2>/dev/null || echo "")
        fi
    fi
    # If still not found, use default ICU library names (icu-uc, icu-io, icu-i18n, icu-data)
    if [ -z "$INTL_LIBS_VALUE" ]; then
        INTL_LIBS_VALUE="-licuuc -licuio -licui18n -licudata"
    else
        # Ensure icuio is included even if extracted from Makefile
        if echo "$INTL_LIBS_VALUE" | grep -qv "icuio"; then
            INTL_LIBS_VALUE="$INTL_LIBS_VALUE -licuio"
        fi
    fi
    INTL_LIBS_ESCAPED=$(echo "$INTL_LIBS_VALUE" | sed 's/\$/$$$$/g')
    
    awk -v cli_libs="$CLI_LIBS_ESCAPED" \
        -v fuzzer_libs="$FUZZER_LIBS_ESCAPED" \
        -v onig_libs="$ONIG_LIBS_ESCAPED" \
        -v intl_libs="$INTL_LIBS_ESCAPED" \
        '/^INTL_SHARED_LIBADD[ :=]/ {
            print $0
            next
        }
        /^EXTRA_LIBS[ :=]/ {
            if (match($0, /^EXTRA_LIBS[ :=] +/)) {
                existing = substr($0, RLENGTH + 1)
                gsub(/^[ \t]+|[ \t]+$/, "", existing)
                gsub(/[ \t]*=[ \t]*/, " ", existing)
                gsub(/[ \t]+/, " ", existing)
                gsub(/^[ \t]+|[ \t]+$/, "", existing)
                libs_to_add = ""
                if (existing !~ /libonig/ && existing !~ /onig/) {
                    libs_to_add = libs_to_add " " onig_libs
                }
                if (intl_libs != "" && (existing !~ /icuuc/ || existing !~ /icuio/ || existing !~ /icui18n/ || existing !~ /icudata/)) {
                    libs_to_add = libs_to_add " " intl_libs
                }
                if (libs_to_add != "" || cli_libs != "") {
                    print "EXTRA_LIBS := " existing libs_to_add " " cli_libs
                } else {
                    print "EXTRA_LIBS := " existing
                }
            } else {
                libs_to_add = onig_libs
                if (intl_libs != "") {
                    libs_to_add = libs_to_add " " intl_libs
                }
                print "EXTRA_LIBS := " libs_to_add " " cli_libs
            }
            next
        }
        /^FUZZING_LIB[ :=]/ {
            if (match($0, /^FUZZING_LIB[ :=] +/)) {
                existing = substr($0, RLENGTH + 1)
                gsub(/^[ \t]+|[ \t]+$/, "", existing)
                gsub(/[ \t]*=[ \t]*/, " ", existing)
                gsub(/[ \t]+/, " ", existing)
                gsub(/^[ \t]+|[ \t]+$/, "", existing)
            }
            libs_to_add = onig_libs
            if (intl_libs != "") {
                libs_to_add = libs_to_add " " intl_libs
            }
            print "FUZZING_LIB := " libs_to_add " " fuzzer_libs
            next
        }
        /^MBSTRING_SHARED_LIBADD[ :=]/ {
            if (match($0, /^MBSTRING_SHARED_LIBADD[ :=] +/)) {
                existing = substr($0, RLENGTH + 1)
                if (existing !~ /libonig/ && existing !~ /onig/) {
                    print "MBSTRING_SHARED_LIBADD := " existing " " onig_libs
                } else {
                    print $0
                }
            } else {
                print "MBSTRING_SHARED_LIBADD := " onig_libs
            }
            next
        }
        { print }' \
        Makefile > "$TMP_MAKEFILE"
    mv "$TMP_MAKEFILE" Makefile
fi

make -j$(nproc) clean

# build oniguruma and link statically
pushd oniguruma
autoreconf -vfi
# Clear LDFLAGS/LIBS for oniguruma configure (it's a static library, doesn't need collabfuzz)
# Note: We don't restore them for oniguruma make since it's just a static library
unset LDFLAGS
unset LIBS
./configure --disable-shared
make -j$(nproc)
popd

make -j$(nproc)

# Generate seed corpora
sapi/cli/php sapi/fuzzer/generate_unserialize_dict.php
sapi/cli/php sapi/fuzzer/generate_parser_corpus.php

FUZZERS="php-fuzz-json php-fuzz-exif php-fuzz-mbstring php-fuzz-unserialize php-fuzz-parser"
for fuzzerName in $FUZZERS; do
	cp sapi/fuzzer/$fuzzerName "$OUT/${fuzzerName/php-fuzz-/}"
done

for fuzzerName in `ls sapi/fuzzer/corpus`; do
    mkdir -p "$TARGET/corpus/${fuzzerName}"
    mkdir -p "/corpus/${fuzzerName}"
    cp sapi/fuzzer/corpus/${fuzzerName}/* "$TARGET/corpus/${fuzzerName}/"
    cp sapi/fuzzer/corpus/${fuzzerName}/* "/corpus/${fuzzerName}/"
done
