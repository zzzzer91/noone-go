# Noone

A Go port of Shadowsocks server. Currently, the only supported cipher is AES-128-CTR.

## Build

```bash
$ ./compile.sh
```

## Usage

```bash
$ cd bin
$ noone -c config.json
```

Or run Noone in the background:

```bash
$ nohup noone -c config.json 2>&1 > noone.log &
```
