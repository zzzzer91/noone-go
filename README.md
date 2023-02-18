# Noone

Another tunnel written in pure Go. Shadowsocks and Trojan support.

## Build

```bash
$ ./compile.sh
```

## Usage

```bash
$ cd bin
$ ./noone -c config.json
```

Or run Noone in the background:

```bash
$ nohup ./noone-server -c config.yaml 2>&1 > noone.log &
```
