FROM centos:latest
MAINTAINER Marcello Paris <marcello.paris@gmail.com>

RUN mkdir /source
RUN cd /etc/yum.repos.d/
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
RUN yum update -y

RUN yum install -y \
    epel-release

RUN yum install -y \
    net-tools pciutils htop wget unzip git telnet which tar lzip

RUN yum install -y \
    make autoconf automake libtool gcc clang cmake

RUN yum install -y \
    flex bison

RUN yum install -y \
    python3 python3-libs python3-devel python3-pip

RUN python3 -m pip install --upgrade pip setuptools

# building z3 from sources
RUN cd /source && \
    wget https://github.com/Z3Prover/z3/archive/z3-4.8.15.tar.gz && \
    tar xvf z3-4.8.15.tar.gz && \
    cd z3-z3-4.8.15 && \
    python3 scripts/mk_make.py && \
    cd build && \
    make -j 8 && make install && \
    rm -rf /source/z3-z3-4.8.15
# building gmp from sources
#RUN cd /source && \
#    wget https://gmplib.org/download/gmp/gmp-6.2.0.tar.lz && \
#    lzip -d gmp-6.2.0.tar.lz && \
#    tar xvf gmp-6.2.0.tar && \
#    cd gmp-6.2.0 && \
#    ./configure && make -j 8 && make install && ldconfig && \
#    rm -rf /source/gmp-6.2.0

# building pbc from sources
#RUN cd /source && \
#    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
#    tar xvf pbc-0.5.14.tar.gz && \
#    cd pbc-0.5.14 && \
#    ./configure && make -j 8 && make install && \
#    echo "/usr/local/lib" > /etc/ld.so.conf.d/pbc.conf && ldconfig -v && \
#    rm -rf /source/pbc-0.5.14

RUN wget https://dl.google.com/go/go1.17.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz

RUN yum install -y \
    redis

RUN yum install -y \
    leveldb leveldb-devel


#RUN cd /source && \
#    git clone https://github.com/miracl/MIRACL

ENV PATH="${PATH}:/usr/local/go/bin"
RUN go get google.golang.org/grpc
RUN mkdir /mosaic
ADD ./abe /mosaic/abe
ADD ./lib/mosaic.go /mosaic/lib
ADD go.mod /mosaic
ADD go.sum /mosaic
ADD ./sclient_side /mosaic/sclient_side
RUN mkdir /mosaic/new_files
RUN mkdir /mosaic/new_files/user_keys
RUN cp /mosaic/sclient_side/attributes /mosaic/new_files
RUN cp /mosaic/sclient_side/ct1 /mosaic/new_files
RUN cp /mosaic/sclient_side/ct2 /mosaic/new_files
RUN cp /mosaic/sclient_side/sig_master_pub.json /mosaic/new_files
RUN cp /mosaic/sclient_side/org.json /mosaic/new_files
RUN cp /mosaic/sclient_side/kk@org1.json /mosaic/new_files
#WORKDIR /mosaic/sclient_side/RPI_Registration
#RUN go run Registration.go
WORKDIR /mosaic
RUN go get github.com/xlzd/gotp
#RUN go run /sclient_side/RPI_Registration/Registration.go
CMD ["/bin/bash"]
