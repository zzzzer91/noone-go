#!/bin/bash

ABSOLUTE_PROJECT_PATH="$(cd "$(dirname "$0")" || exit;pwd)"

CMD_DIR="${ABSOLUTE_PROJECT_PATH}/cmd"
BIN_DIR="${ABSOLUTE_PROJECT_PATH}/bin"

if [ ! -d "${BIN_DIR}" ]; then
  mkdir "${BIN_DIR}"
fi

echo '编译中...'
# -w 去掉调试信息，得到的程序就不能用 gdb 调试了
# -s 去掉符号表，panic 时候的 stack trace 就没有任何文件名/行号信息了，这个等价于普通 C/C++ 程序被 strip 的效果
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-w -s" -o "${BIN_DIR}/noone" "${CMD_DIR}/main.go"
if [ $? -ne 0 ]; then
  echo '编译失败！'
else
  echo '编译成功！'
fi