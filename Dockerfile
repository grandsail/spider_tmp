FROM ubuntu:18.04
EXPOSE 1935 1985 8080 8000/udp 10080/udp

USER root
RUN apt-get update
RUN apt-get install -y gcc g++ make patch unzip pkg-config libcurl4-openssl-dev

COPY trunk /srs/trunk
WORKDIR /srs/trunk
RUN ./configure --ffmpeg-fit=off
RUN make -j8

RUN rm -r src && rm -r 3rdparty

# NOTEG: 使用新的仓库地址替换“regist.../diver-srs”，冒号后为版本号
# docker build -t registry.cn-hangzhou.aliyuncs.com/spider-bupt/spider:v0-test --push .

# build 多平台
# docker buildx build --platform linux/amd64,linux/arm64 -t registry.cn-hangzhou.aliyuncs.com/bupt-srs/diver-srs:spider-v0.2 --push .

# linux
# sudo docker run --rm -i --net host registry.cn-hangzhou.aliyuncs.com/bupt-srs/diver-srs:local-v0.1 ./objs/srs -c conf/rtc.conf

# mac
# docker run --rm -i -p 1935:1935 -p 1985:1985 -p 8080:8080 -p 8000:8000/udp registry.cn-hangzhou.aliyuncs.com/bupt-srs/diver-srs:local-v0.1 ./objs/srs -c conf/rtc.conf

# android
# docker run --rm -i -p 1935:1935 -p 1985:1985 -p 8080:8080 -p 8000:8000/udp registry.cn-hangzhou.aliyuncs.com/bupt-srs/diver-srs:multiplatform-v0.2 ./objs/srs -c conf/rtc.conf