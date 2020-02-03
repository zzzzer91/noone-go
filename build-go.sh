#!/bin/bash

ABSOLUTE_PROJECT_PATH="$(cd "$(dirname "$0")" || exit;pwd)"

CMD_DIR="${ABSOLUTE_PROJECT_PATH}/cmd"
BIN_DIR="${ABSOLUTE_PROJECT_PATH}/bin"

if [ ! -d "${BIN_DIR}" ]; then
  mkdir "${BIN_DIR}"
fi

echo "编译中..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${BIN_DIR}/noone" "${CMD_DIR}/main.go"
echo '编译完成！'