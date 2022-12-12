# dlna_proxy
DLNA proxy between mobile phone and TV, you can use shell script to change the playback address or change the protocol, such as RTMP(by ffmpeg)

DLNA代理，当使用手机进行投屏操作时，可以本工具提供的接口，截获媒体播放地址，或者在shell脚本中对投屏地址进行转换，例如大部分网站都是采用HLS方式来提供在线点播服务，但部分电视只能使用单线程进行下载播放，造成播放时频繁卡顿，因此可以使用其他工具进行本地CDN预读，加快下载速度

# 命令行
    -d string      当设备存在多个网卡，应当设置一个响应地址，用于手机进行访问
    -h int         本地HTTP服务器地址，默认8808
    -s string       脚本文件路径
    -t string       电视的IP及端口
    -timeout int    超时时长，用于搜索模式
    -u string       UUID，不填则随机生成

# 其他
暂时还不完善，部分电视响应的XML文档格式可能不符合规范，导致无法使用
