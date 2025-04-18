# 🧮 iRule: WebSocket Frame Rate Limiter

This iRule limits the number of WebSocket frames that a client IP can send using the `WS_CLIENT_FRAME` event. The rate is enforced per client IP over a 1-second window and helps prevent abuse or denial-of-service via excessive WebSocket traffic.

## ✨ Features

- 🔒 Per-client rate limiting (IP-based)
- ⚙️ Configurable max frames per second
- 🕒 Throttle behavior using `after` instead of rejecting frames
- 🧾 Debug logging for visibility and tuning
- 🛡️ Error handling to avoid runtime disruptions

## ⚙️ Configuration Parameters (`RULE_INIT`)

| Variable                     | Description                                               | Default |
|-----------------------------|------------------------------------------------------------|---------|
| `static::wsfl_maxRate`      | Max allowed frames per second per TCP session              | 5       |
| `static::wsfl_debugLog`     | Enable debug logging (1 = on, 0 = off)                     | 1       |
| `static::wsfl_autoRateLimitValue` | Auto-calculated delay in ms between frames if limit is exceeded | Computed |

## 🔍 How it Works

- Each client IP gets a unique `<IP>_<client TCP port>` key in the session table.
- The key is incremented every time a WebSocket frame is seen.
- If the count exceeds the allowed `maxRate`, the `after` command delays further frame handling to throttle the connection.
- The counter is automatically removed after `timeout` seconds to allow rate recovery.

## 🐛 Example Debug Logs

If debug logging is enabled (`static::wsfl_debugLog == 1`), log entries will appear in `/var/log/ltm` like:
```
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=2
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=3
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=4
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=5
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=2
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=3
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=4
<WS_CLIENT_FRAME>: 192.168.1.1: frameCount=5
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
<WS_CLIENT_FRAME>: 192.168.1.1 exceeded max WS frames per second. Rate-Limiting to 5/second
```