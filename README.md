# IPTV M3U

## Limit
- Sichuan ChengDu IPTV only
- DHCP network config
  - vender class -> SCITV
  - hostname -> stbid
  - dns advertised by peer

## Dependencies
openwrt packages
```bash
lua-cjson
lua-openssl
luasocket
```

## Usage
```text
Usage: lua iptv.lua [options]
Options:
  -h, --help      Show this help message
  --network       Set the network device [eth0]
  --config        Set the configuration path [ctc_conf.json]
  --output        Set the m3u output path [iptv.m3u]
  --http          Set http [ip:port] for rtp/udp to http
```

ctc_conf.json
```json
{
    "mpassword": "",
    "userid": "",
    "stbid": "",
    "supporthd": "1",
    "stbtype": "",
    "stbversion": "",
    "conntype": "dhcp",
    "productpackageid": "-1",
    "mac": "",
    "userfield": "0",
    "softwareversion": "",
    "useragent": ""
}
```

