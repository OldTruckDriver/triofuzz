======================= libpng =======================

cd tools/captain

export FUZZER=triofuzz
export TARGET=libpng 
./build.sh

mkdir -p /path/to/magma/tools/captain/libpng

export FUZZER=triofuzz 
export TARGET=libpng 
export PROGRAM=libpng_read_fuzzer 
export SHARED=./libpng 
export POLL=5 
export TIMEOUT=24h 
./start.sh


======================= SQLite3 =======================

cd tools/captain

docker stop $(docker ps -q)
docker system prune -a



export FUZZER=triofuzz
export TARGET=sqlite3 
./build.sh

mkdir -p /path/to/magma/tools/captain/sqlite3

export FUZZER=triofuzz
export TARGET=sqlite3 
export PROGRAM=sqlite3_fuzz 
export SHARED=./sqlite3 
export POLL=5 
export TIMEOUT=24h 
./start.sh

======================= openssl =======================

cd tools/captain
mkdir -p /path/to/magma/tools/captain/openssl

export FUZZER=triofuzz 
export TARGET=openssl 
./build.sh



export FUZZER=triofuzz 
export TARGET=openssl 
export PROGRAM=client 
export SHARED=./openssl 
export POLL=5 
export TIMEOUT=24h 
./start.sh


======================= libsndfile =======================

cd tools/captain
mkdir -p /path/to/magma/tools/captain/libsndfile

export FUZZER=triofuzz 
export TARGET=libsndfile 
./build.sh



export FUZZER=triofuzz 
export TARGET=libsndfile 
export PROGRAM=sndfile_fuzzer 
export SHARED=./libsndfile 
export POLL=5 
export TIMEOUT=24h 
./start.sh



======================= poppler =======================

cd tools/captain
mkdir -p /path/to/magma/tools/captain/poppler

export FUZZER=triofuzz 
export TARGET=poppler 
./build.sh



export FUZZER=triofuzz 
export TARGET=poppler 
export PROGRAM=pdf_fuzzer 
export SHARED=./poppler 
export POLL=5 
export TIMEOUT=24h 
./start.sh



======================= libtiff =======================

cd tools/captain
mkdir -p /path/to/magma/tools/captain/libtiff

export FUZZER=collabfuzz_mini 
export TARGET=libtiff 
./build.sh



export FUZZER=triofuzz 
export TARGET=libtiff 
export PROGRAM=tiff_read_rgba_fuzzer 
export SHARED=./libtiff 
export POLL=5 
export TIMEOUT=24h 
./start.sh


======================= libxml2 =======================

cd tools/captain
mkdir -p /path/to/magma/tools/captain/libxml2

export FUZZER=triofuzz 
export TARGET=libtiff 
./build.sh



export FUZZER=triofuzz 
export TARGET=libtiff 
export PROGRAM=tiff_read_rgba_fuzzer 
export SHARED=./libtiff 
export POLL=5 
export TIMEOUT=24h 
./start.sh