# Noone

Another tunnel written in pure Go. Shadowsocks and Trojan support.

## Build

```bash
$ ./compile.sh
```

## Usage

```bash
$ cd bin
$ ./noone-server -c config.yaml
```

Or run Noone in the background:

```bash
$ nohup ./noone-server -c config.yaml 2>&1 > noone.log &
```
