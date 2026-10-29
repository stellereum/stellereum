# DNS-разделение: testnet vs mainnet

Требование: чёткое разделение — пользователь всегда понимает, что он в **тестнете**, а не в mainnet-эксплорере.

## Рекомендуемая схема (поменять DNS-записи)

| Сайт              | Testnet (этот проект)              | Mainnet (другой проект/потом)       |
|-------------------|------------------------------------|-------------------------------------|
| Explorer          | `testnet-explorer.example.com`     | `explorer.example.com`              |
| Faucet            | `testnet-faucet.example.com`       | — (у mainnet крана нет)             |

Альтернатива: `explorer-testnet.example.com` + `faucet-testnet.example.com`.

## DNS-записи (пример для Cloudflare / Route53 / любого NS)

```text
; Explorer (отдельный хостинг/bucket)
testnet-explorer   300  IN  CNAME  hosting-testnet-explorer.example.net.

; Faucet (отдельный хостинг — другой origin!)
testnet-faucet     300  IN  CNAME  hosting-testnet-faucet.example.net.
```

- Два **разных** origin/деплоймента (не поддомен-алиас на один сайт) — иначе разделение фиктивное.
- TLS: отдельные сертификаты (Let's Encrypt / ACM) на каждый хост.
- HSTS + redirect http→https.

## UI-маркировка (уже реализовано в коде)

- В шапке обоих сайтов — amber-полоса `● TESTNET • chainId 5757 • rpc.stellereum.org`.
- Фавикон и логотип с пометкой `TEST`, title вкладки: `… — Testnet Explorer`.
- Кран дополнительно: предупреждение `Не отправляйте mainnet-активы. Тестовые монеты не имеют ценности.` + ссылка на эксплорер тестнета (не mainnet).
- В коде нет переключателя сетей и нет mainnet RPC — перепутать невозможно.

## Чеклист после смены DNS

1. `dig testnet-explorer.example.com` и `dig testnet-faucet.example.com` резолвятся на разные цели.
2. Открыть оба сайта — виден бейдж TESTNET.
3. Проверить, что поиск в эксплорере ищет только по testnet chainId 5757.
4. Кран выдаёт только на нативные 64-hex адреса в chainId 5757.
