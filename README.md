# Noone

A Go port of Shadowsocks server. Currently, the only supported cipher is AES-128-CTR.

## Build

```bash
$ ./compile.sh
```

## Usage

```bash
$ cd bin
$ noone -c <config file>
```

Or run Noone in the background:

```bash
$ nohup noone -c <config file> >> noone.log &
```
