source .venv/bin/activate && pip install "setuptools<81" wheel

docker stop $(docker ps -q)
docker system prune -a


export FUZZER_NAME=ecofuzz_lc_monitor
export BENCHMARK_NAME=harfbuzz_hb-shape-fuzzer
make run-$FUZZER_NAME-$BENCHMARK_NAME

export FUZZER_NAME=aflpp_probe
export BENCHMARK_NAME=libpng_libpng_read_fuzzer
make run-$FUZZER_NAME-$BENCHMARK_NAME

export DOCKER_API_VERSION=1.44


PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks rapidjson_fuzzer miniz_zip_fuzzer cppitertools_fuzz_cppitertools libexif_exif_loader_fuzzer \
  --experiment-name triofuzz-4cores-3trails-fix6 \
  --fuzzers triofuzz


capstone_fuzz_disasmv5 libaom_av1_dec_fuzzer cmake_xml_parser_fuzzer c-ares_ares_parse_reply_fuzzer libunwind_fuzz_libunwind


PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks cmake_xml_parser_fuzzer miniz_zip_fuzzer cppitertools_fuzz_cppitertools libaom_av1_dec_fuzzer libunwind_fuzz_libunwind \
  --experiment-name baseline-10trails-fix4 \
  --fuzzers aflplusplus ecofuzz mopt muofuzz

PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks cmake_xml_parser_fuzzer miniz_zip_fuzzer cppitertools_fuzz_cppitertools libaom_av1_dec_fuzzer libunwind_fuzz_libunwind \
  --experiment-name aflppp-3trails-fix1 \
  --fuzzers aflplusplus_parallel

harfbuzz_hb-shape-fuzzer libjpeg-turbo_libjpeg_turbo_fuzzer mbedtls_fuzz_dtlsclient libpng_libpng_read_fuzzer lcms_cms_transform_fuzzer 

stb_stbi_read_fuzzer lcms_cms_transform_fuzzer vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer

PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks c-ares_ares_parse_reply_fuzzer rapidjson_fuzzer capstone_fuzz_disasmv5 libaom_av1_dec_fuzzer cmake_xml_parser_fuzzer miniz_zip_fuzzer \
  --experiment-name triofuzzossfuzz1 \
  --fuzzers triofuzz 


cppitertools_fuzz_cppitertools c-ares_ares_parse_reply_fuzzer rapidjson_fuzzer yaml-cpp_load_fuzzer cmake_xml_parser_fuzzer libaom_av1_dec_fuzzer capstone_fuzz_disasmv5 cmark_cmark_fuzzer libunwind_fuzz_libunwind 

jsoncpp_jsoncpp_fuzzer woff2_convert_woff2ttf_fuzzer lcms_cms_transform_fuzzer bloaty_fuzz_target zlib_zlib_uncompress_fuzzer glslang_compile_fuzzer

harfbuzz_hb-shape-fuzzer vorbis_decode_fuzzer zlib_zlib_uncompress_fuzzer libpng_libpng_read_fuzzer mbedtls_fuzz_dtlsclient libjpeg-turbo_libjpeg_turbo_fuzzer openssl_x509 re2_fuzzer stb_stbi_read_fuzzer woff2_convert_woff2ttf_fuzzer lcms_cms_transform_fuzzer jsoncpp_jsoncpp_fuzzer 



rapidjson_fuzzer yaml-cpp_load_fuzzer cmake_xml_parser_fuzzer libaom_av1_dec_fuzzer c-ares_ares_parse_reply_fuzzer  capstone_fuzz_disasmv5 libunwind_fuzz_libunwind cmark_cmark_fuzzer libexif_exif_loader_fuzzer cppitertools_fuzz_cppitertools

miniz_zip_fuzzer highwayhash_highwayhash_fuzzer libidn2_libidn2_to_ascii_8z_fuzzer

sqlite3_ossfuzz curl_curl_fuzzer_http libxml2_xml freetype2_ftfuzzer

export LLVM_PROFDATA_BIN=llvm-profdata-22
export LLVM_COV_BIN=llvm-cov-22

PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks libidn2_libidn2_to_ascii_8z_fuzzer \
  --experiment-name mxossfuzz12 \
  --fuzzers muofuzz xfuzz_opt


lz4_decompress_fuzzer libidn2_libidn2_to_ascii_8z_fuzzer




libjpeg-turbo_libjpeg_turbo_fuzzer mbedtls_fuzz_dtlsclient openssl_x509 re2_fuzzer


PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks harfbuzz_hb-shape-fuzzer \
  --experiment-name moptlcmonitor1 \
  --fuzzers mopt_lc_monitor



PYTHONPATH=. python3 experiment/run_experiment.py \
--experiment-config experiment-config.yaml \
--benchmarks harfbuzz_hb-shape-fuzzer \
--experiment-name harfbuzztracking1 \
--fuzzers aflplusplus_operator_tracking


export FUZZER_NAME=triofuzz
export BENCHMARK_NAME=stb_stbi_read_fuzzer
make run-$FUZZER_NAME-$BENCHMARK_NAME

PYTHONPATH=. python3 analysis/generate_operator_report.py \
    --experiment-dir /tmp/experiment-data/harfbuzztracking1 \
    --output-dir report-data/tracking_operator_harfbuzz1 \
    --name "harfbuzztracking1"

PYTHONPATH=. python3 analysis/generate_report.py \
    --experiment-names tracking1 \
    --report-dir report-data/tracking1

docker build \
--tag gcr.io/fuzzbench/builders/collabfuzz/freetype2_ftfuzzer-intermediate \
--no-cache \
--build-arg BUILDKIT_INLINE_CACHE=1 \
--build-arg parent_image=gcr.io/fuzzbench/builders/benchmark/freetype2_ftfuzzer \
--file fuzzers/collabfuzz/builder.Dockerfile

cd /home/ricky/Desktop/test/fuzzbench

sudo PYTHONPATH=. /home/ricky/Desktop/test/fuzzbench/.venv/bin/python manual_cov_openh264_d25.py
sudo PYTHONPATH=. /home/ricky/Desktop/test/fuzzbench/.venv/bin/python  manual_cov_guetzli_d31.py


LLVM_PROFDATA_BIN=/usr/bin/llvm-profdata-18 \
LLVM_COV_BIN=/usr/bin/llvm-cov-18 \
PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks harfbuzz_hb-shape-fuzzer \
  --experiment-name harfbuzz \
  --fuzzers collabfuzz aflplusplus libfuzzer

PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks zlib_zlib_uncompress_fuzzer re2_fuzzer bloaty_fuzz_target mbedtls_fuzz_dtlsclient stb_stbi_read_fuzzer woff2_convert_woff2ttf_fuzzer lcms_cms_transform_fuzzer \
  --experiment-name baseline8 \
  --fuzzers aflplusplus libfuzzer honggfuzz mopt muofuzz xfuzz_opt




PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks harfbuzz_hb-shape-fuzzer mbedtls_fuzz_dtlsclient vorbis_decode_fuzzer libpng_libpng_read_fuzzer libjpeg-turbo_libjpeg_turbo_fuzzer lcms_cms_transform_fuzzer zlib_zlib_uncompress_fuzzer jsoncpp_jsoncpp_fuzzer stb_stbi_read_fuzzer openssl_x509 \
  --experiment-name aflppparallel \
  --fuzzers aflplusplus_parallel


PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks lcms_cms_transform_fuzzer zlib_zlib_uncompress_fuzzer jsoncpp_jsoncpp_fuzzer stb_stbi_read_fuzzer openssl_x509  \
  --experiment-name aflppparallel2 \
  --fuzzers aflplusplus_ts_parallel


PYTHONPATH=. python3 experiment/run_experiment.py \
  --experiment-config experiment-config.yaml \
  --benchmarks zlib_zlib_uncompress_fuzzer jsoncpp_jsoncpp_fuzzer stb_stbi_read_fuzzer \
  --experiment-name collabfuzzafl2 \
  --fuzzers collabfuzz_afl




harfbuzz_hb-shape-fuzzer libpng_libpng_read_fuzzer mbedtls_fuzz_dtlsclient vorbis_decode_fuzzer libjpeg-turbo_libjpeg_turbo_fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer systemd_fuzz-link-parser




sudo rm -rf /tmp/experiment-data/ /tmp/report-data/


export BENCHMARK_NAME=abseil-cpp
export BENCHMARK_NAME=pcre2_pcre2_fuzzer
export BENCHMARK_NAME=libarchive_libarchive_fuzzer
export BENCHMARK_NAME=libavif_avif_decode_fuzzer
export BENCHMARK_NAME=libheif_file-fuzzer
export BENCHMARK_NAME=libspng_spng_read_fuzzer
export BENCHMARK_NAME=libwebp_animencoder_fuzzer_animencoder.animencodertest
export BENCHMARK_NAME=boringssl_client
export BENCHMARK_NAME=hiredis_format_command_fuzzer
export BENCHMARK_NAME=protobuf-c_fuzzer
export BENCHMARK_NAME=openjpeg_opj_decompress_fuzzer_jp2
export BENCHMARK_NAME=proj4_proj_crs_to_crs_fuzzer
export BENCHMARK_NAME=ecc-diff-fuzzer_fuzz_ec_noblocker


export BENCHMARK_NAME=flex_fuzz-scanopt


## low performance
export BENCHMARK_NAME=assimp_assimp_fuzzer
export BENCHMARK_NAME=openjpeg_opj_decompress_fuzzer_jp2 // no seed
export BENCHMARK_NAME=libwebsockets_lws_upng_inflate_fuzzer // no socket connection
<!-- export BENCHMARK_NAME=giflib_dgif_target -->
export BENCHMARK_NAME=flac_fuzzer_exo
export BENCHMARK_NAME=unrar_unrar_fuzzer
export BENCHMARK_NAME=bluez_fuzz_xml // no seed
export BENCHMARK_NAME=brunsli_fuzz_decode
export BENCHMARK_NAME=cfengine_string_fuzzer
export BENCHMARK_NAME=elfutils_fuzz-dwfl-core
export BENCHMARK_NAME=libjxl_djxl_fuzzer

## bug
export BENCHMARK_NAME=libxml2_xml
export BENCHMARK_NAME=curl_curl_fuzzer_http
export BENCHMARK_NAME=zstd_stream_decompress
export BENCHMARK_NAME=freetype2_ftfuzzer
export BENCHMARK_NAME=jansson_json_load_dump_fuzzer
export BENCHMARK_NAME=libass_libass_fuzzer
export BENCHMARK_NAME=sqlite3_ossfuzz
export BENCHMARK_NAME=libfuse_fuzz_optparse
export BENCHMARK_NAME=s2geometry_s2_fuzzer
export BENCHMARK_NAME=openthread_ot-ip6-send-fuzzer
export BENCHMARK_NAME=mdbtools_fuzz_mdb
export BENCHMARK_NAME=file_magic_fuzzer
export BENCHMARK_NAME=libxslt_xpath
export BENCHMARK_NAME=libtiff_tiff_read_rgba_fuzzer



export BENCHMARK_NAME=libpng_libpng_read_fuzzer
export BENCHMARK_NAME=jsoncpp_jsoncpp_fuzzer
export BENCHMARK_NAME=zlib_zlib_uncompress_fuzzer
export BENCHMARK_NAME=woff2_convert_woff2ttf_fuzzer
export BENCHMARK_NAME=libjpeg-turbo_libjpeg_turbo_fuzzer
export BENCHMARK_NAME=bloaty_fuzz_target
export BENCHMARK_NAME=mruby_mruby_fuzzer_8c8bbd
export BENCHMARK_NAME=lcms_cms_transform_fuzzer
export BENCHMARK_NAME=openssl_x509
export BENCHMARK_NAME=mbedtls_fuzz_dtlsclient
export BENCHMARK_NAME=harfbuzz_hb-shape-fuzzer
export BENCHMARK_NAME=vorbis_decode_fuzzer
export BENCHMARK_NAME=re2_fuzzer
export BENCHMARK_NAME=stb_stbi_read_fuzzer
export BENCHMARK_NAME=libpcap_fuzz_both
export BENCHMARK_NAME=giflib_dgif_target
export BENCHMARK_NAME=brotli_decode_fuzzer
export BENCHMARK_NAME=bzip2_bzip2_decompress_target
export BENCHMARK_NAME=c-ares_ares_parse_reply_fuzzer
export BENCHMARK_NAME=capstone_fuzz_disasmv5
export BENCHMARK_NAME=libaom_av1_dec_fuzzer

export BENCHMARK_NAME=libevent_http_fuzzer
export BENCHMARK_NAME=libidn2_libidn2_to_ascii_8z_fuzzer
export BENCHMARK_NAME=libsndfile_sndfile_fuzzer
export BENCHMARK_NAME=libtiff_tiff_read_rgba_fuzzer
export BENCHMARK_NAME=libvpx_vpx_dec_fuzzer_vp9

export BENCHMARK_NAME=libyaml_libyaml_parser_fuzzer
export BENCHMARK_NAME=libzip_zip_read_fuzzer
export BENCHMARK_NAME=lz4_decompress_fuzzer
export BENCHMARK_NAME=nghttp2_nghttp2_fuzzer
export BENCHMARK_NAME=tinyxml2_xmltest
export BENCHMARK_NAME=systemd_fuzz-link-parser


export BENCHMARK_NAME=exiv2_fuzz-read-write
export BENCHMARK_NAME=expat_xml_parse_fuzzer
export BENCHMARK_NAME=jbig2dec_jbig2_fuzzer
export BENCHMARK_NAME=libexif_exif_loader_fuzzer


export BENCHMARK_NAME=libraw_libraw_fuzzer

export BENCHMARK_NAME=libssh2_ssh2_client_fuzzer

export BENCHMARK_NAME=miniz_zip_fuzzer


export BENCHMARK_NAME=pugixml_fuzz_parse
export BENCHMARK_NAME=rapidjson_fuzzer

export BENCHMARK_NAME=snappy_snappy_uncompress_fuzzer
export BENCHMARK_NAME=yaml-cpp_load_fuzzer
export BENCHMARK_NAME=cctz_fuzz_cctz
export BENCHMARK_NAME=cmake_xml_parser_fuzzer
export BENCHMARK_NAME=cpuinfo_fuzz_cpuinfo
export BENCHMARK_NAME=duckdb_parse_fuzz_test

export BENCHMARK_NAME=glslang_compile_fuzzer
export BENCHMARK_NAME=guetzli_guetzli_fuzzer


export BENCHMARK_NAME=libhtp_fuzz_htp_c
export BENCHMARK_NAME=libunwind_fuzz_libunwind

export BENCHMARK_NAME=lua_fuzz_lua
export BENCHMARK_NAME=mariadb_fuzz_json
export BENCHMARK_NAME=mdbtools_fuzz_mdb
export BENCHMARK_NAME=meshoptimizer_codecfuzzer
export BENCHMARK_NAME=openh264_decoder_fuzzer
export BENCHMARK_NAME=wabt_wasm_objdump_fuzzer


export BENCHMARK_NAME=cgif_cgif_fuzzer
export BENCHMARK_NAME=cmark_cmark_fuzzer
export BENCHMARK_NAME=coturn_fuzzstun
export BENCHMARK_NAME=cppitertools_fuzz_cppitertools
export BENCHMARK_NAME=cpuinfo_fuzz_cpuinfo


export BENCHMARK_NAME=espeak-ng_ssml-fuzzer
export BENCHMARK_NAME=exprtk_exprtk_fuzzer


export BENCHMARK_NAME=gpsd_fuzzjson
export BENCHMARK_NAME=guetzli_guetzli_fuzzer
export BENCHMARK_NAME=hdf5_h5_read_fuzzer
export BENCHMARK_NAME=highwayhash_highwayhash_fuzzer
export BENCHMARK_NAME=hiredis_format_command_fuzzer
export BENCHMARK_NAME=



export FUZZER_NAME=aflplusplus_ts_parallel
export BENCHMARK_NAME=libpng_libpng_read_fuzzer
make run-$FUZZER_NAME-$BENCHMARK_NAME

libpng_libpng_read_fuzzer
woff2_convert_woff2ttf_fuzzer
libxml2_xml
libjpeg-turbo_libjpeg_turbo_fuzzer
sqlite3_ossfuzz
bloaty_fuzz_target
lcms_cms_transform_fuzzer




docker logs e66a97214415 2>&1 | grep -E "(Setting up|CrashRecovery|fork-server|in-process|Total edges)" | head -50








make test-run-$FUZZER_NAME-$BENCHMARK_NAME


export FUZZER_NAME=aflplusplus_ts_parallel
export BENCHMARK_NAME=libpng_libpng_read_fuzzer
make debug-builder-$FUZZER_NAME-$BENCHMARK_NAME




$CXX $CXXFLAGS -std=c++11 -fsanitize=address -fprofile-instr-generate -fcoverage-mapping -fsanitize-coverage=trace-pc-guard -g -O1 -I. \
     $SRC/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc \
     -o $OUT/libpng_read_fuzzer \
     /usr/lib/libcollabfuzz.a .libs/libpng16.a \
     -lz -lpthread -lrt -ldl -lm -lcrypto -lc++ -lc++abi

  

cd /out
export LLVM_PROFILE_FILE="output/main_coverage_%p.profraw"
rm -rf output
./libpng_read_fuzzer -dict=seeds/libpng_read_fuzzer.dict -seeds=seeds/projects/libpng -max_total_time=900 -threads=4 -verbose=0 -output=output --disable-stagnation-recovery

--stagnation-recovery-instances 2 --stagnation-detection-window 60 --stagnation-threshold 0.001 --disable-corpus-optimization


llvm-profdata merge -sparse output/main_coverage_*.profraw -o output/combined_coverage.profdata
llvm-cov report ./libpng_read_fuzzer -instr-profile=output/combined_coverage.profdata 