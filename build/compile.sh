cd ..
make clean
make -j 8
cd build
sudo killall uFTP
./uFTP
