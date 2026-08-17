# ACL4SSR Online Mini Maintained

A public SubConverter-compatible replacement for `ACL4SSR_Online_Mini.ini`.

The template keeps the classic ACL4SSR format:

- `[custom]`
- `ruleset=`
- `custom_proxy_group=`
- `enable_rule_generator=true`

The rule data is sourced from [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules). Its upstream files are Mihomo/Clash rule-provider payloads, so this repository converts them into classic `DOMAIN-SUFFIX`, `IP-CIDR`, `IP-CIDR6`, and `PROCESS-NAME` list rules for SubConverter.

## Remote config URL

```text
https://raw.githubusercontent.com/NOWYQS/ACL4SSR_Online_Mini_Maintained/main/ACL4SSR_Online_Mini_Maintained.ini
```

Use this URL as the remote `config=` value in a compatible SubConverter endpoint.

## Generated rule sources

| Generated file | Upstream source | Policy |
|---|---|---|
| `private.list` | `private.txt` | Direct |
| `applications.list` | `applications.txt` | Direct process rules |
| `direct.list` | `direct.txt` | Direct |
| `lancidr.list` | `lancidr.txt` | Direct LAN IP ranges |
| `cncidr.list` | `cncidr.txt` | Direct China IP ranges |
| `reject.list` | `reject.txt` | Reject |
| `proxy.list` | `proxy.txt` | Proxy |
| `gfw.list` | `gfw.txt` | Proxy |
| `tld-not-cn.list` | `tld-not-cn.txt` | Proxy |
| `telegramcidr.list` | `telegramcidr.txt` | Proxy |

## Why GitHub Actions is used

The upstream release files are provider payloads rather than classic ACL4SSR `ruleset=` lists. The daily Action converts them into public raw `.list` files that SubConverter can consume. It commits only when the generated content changes.

The scheduled job runs daily at 03:17 UTC (11:17 Asia/Shanghai), with a manual `workflow_dispatch` option.

## Upstream conversion rules

- `+.example.com` or `*.example.com` becomes `DOMAIN-SUFFIX,example.com`.
- IPv4 CIDR becomes `IP-CIDR,...,no-resolve`.
- IPv6 CIDR becomes `IP-CIDR6,...,no-resolve`.
- Existing classic process rules such as `PROCESS-NAME,...` are preserved.
- Duplicate generated rules are removed deterministically.

This project intentionally publishes converted classic lists, not Mihomo `MRS` or provider YAML files.
