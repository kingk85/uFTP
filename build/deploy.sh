cd ..
# -------------------------------
make clean
make CC=/opt/cross/bin/arm-linux-musleabihf-gcc ENDFLAG=-static
cp build/uFTP /var/www/html/uftpserver.com/downloads/binaries/latest/armhf/uFTP
# ---------------------------------
make clean
make CC=musl-gcc ENDFLAG=-static
cp build/uFTP /var/www/html/uftpserver.com/downloads/binaries/latest/x64/uFTP
cp uftpd.cfg /var/www/html/uftpserver.com/downloads/configuration_sample/uftpd.cfg
cd build