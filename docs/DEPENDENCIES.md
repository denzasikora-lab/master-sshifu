# Зависимости и лицензии

## Клиент и управляющий код

- Python 3.12+, используется только стандартная библиотека. `requirements.txt`
  и установка через pip не требуются. Установщик самого движка совместим
  также с Python 3.9+ для Ubuntu 22.04.
- OpenSSH и системные утилиты macOS: `curl`, `scutil`, `route`, `netstat`,
  `networksetup`, `ipconfig`, `sudo`. Homebrew нужен только как один из способов
  установить Python, код VPN не зависит от Homebrew.
- Git нужен для получения исходников и обновлений.
- Linux VPS: OpenSSH server, Python, CA-сертификаты, systemd, `curl` для проверки.

## sing-box 1.14.3

Исполняемый файл не хранится в Git. Установщик скачивает официальный архив
из релиза SagerNet, сравнивает закрепленный SHA256 до распаковки и проверяет
версию. Данные закреплены в `vendor/releases.json`. Поддерживаемые архивы:
`darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`.

Локально генерируется `vendor/provenance.json` с версией, платформой,
хешем архива и хешем установленного бинарного файла. Он исключен из Git.
Повторная установка использует уже проверенный файл при совпадении хешей.
Клиент перед запуском проверяет версию и хеш бинарного файла по происхождению.

Переход на другую версию требует обновить манифест, ожидаемую версию в коде,
проверить схему конфигурации и повторить регрессионную и ручную приемку.
Не заменяйте бинарный файл случайной сборкой и не отключайте проверку хеша.

Исходники управляющего Python-кода распространяются по [MIT](../LICENSE).
sing-box является отдельным проектом; его лицензионное уведомление сохранено
в [vendor/LICENSE](../vendor/LICENSE). Оно не заменяется лицензией MIT клиента.
Системные программы и Python имеют собственные лицензии. Исходный текст
правовых уведомлений сохранен на языке правообладателей.

## Официальные источники

- [Python для macOS](https://www.python.org/downloads/macos/).
- [Homebrew: установка](https://docs.brew.sh/Installation).
- [Релиз sing-box 1.14.3 и контрольные суммы](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3).
- [Документация sing-box](https://sing-box.sagernet.org/configuration/).
- [OpenSSH: ssh_config](https://man.openbsd.org/ssh_config).
- [OpenSSH: sshd_config](https://man.openbsd.org/sshd_config).
- [OpenSSH: authorized_keys](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).
- [systemd: параметры службы](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
