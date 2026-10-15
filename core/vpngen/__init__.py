# core/vpngen/__init__.py
"""
Нативный генератор VPN-конфигов на инфраструктуре Cloudflare WARP и
Proton VPN — для AmneziaWG, usque (MASQUE), sing-box и mihomo.

Модули:
    keys      — X25519 / Ed25519 / P-256 на чистом Python;
    net       — JSON-запросы через транспорт (напрямую / через обход / авто);
    presets   — DNS, адреса Cloudflare, маски I1, AllowedIPs (данные);
    warp      — регистрация WARP: WireGuard и MASQUE, свой API или сервис;
    proton    — Proton VPN через сервис-генератор, ключ создаётся у нас;
    render    — профиль → текст конфига движка;
    generate  — оркестратор: опции → профиль → конфиги → сохранение.

Точки входа: ``generate.options()``, ``generate.generate(request)``,
``generate.save_output(target, name, text)``, ``proton.servers(transport)``.
"""
