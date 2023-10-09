curl https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz --output libpng-1.6.37.tar.xz
tar -xvf libpng-1.6.37.tar.xz

rm -rf libpng-1.6.37.tar.xz

cd libpng-1.6.37 && CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --enable-shared=no --with-pic=yes --enable-hardware-optimizations=yes && make

