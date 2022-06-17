#!/bin/sh

killall ffmpeg > /dev/null 2>&1

if [ -z ${1} ]; then
  exit
fi

sh -c "ffmpeg -re -i \"${1}\" -c copy -bsf:a aac_adtstoasc -f flv -y \"rtmp://192.168.0.100:1935/live/livestream\"" &

cat << EOF
{
	"url": "rtmp://192.168.0.100:1935/live/livestream"
}
EOF
