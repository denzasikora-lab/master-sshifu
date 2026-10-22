# Полное воспроизведение Master SSHifu

Ниже один базовый вариант: Mac как клиент и VPS с Ubuntu/Debian как сервер.
Команды каждого раздела выполняются только в указанной среде. Существующие
VPN, ключи и серверы автоматически не перенастраиваются.

Замените `203.0.113.10` на публичный IPv4 своего VPS. Это пример из
документального диапазона, он не является работающим сервером.
Обычный SSH-порт в примерах 22; если у вас другой, замените его во всех шагах.

## 1. Что подготовить

- Mac с доступом в интернет, Terminal и учетной записью с sudo.
- VPS с публичным IPv4, Ubuntu 22.04+ или Debian 12+, доступом администратора
  через SSH и консолью провайдера на случай ошибки.
- Разрешенный входящий TCP-порт SSH в панели провайдера и серверном firewall.
- Исходящий доступ VPS к интернету, включая HTTPS и DNS.
- Доступ Mac и VPS к GitHub для клонирования и загрузки зависимости.

Не открывайте TCP/UDP 43190 наружу. Между Mac и VPS нужен только SSH.
Приведенные ниже команды не включают firewall заново и не закрывают
административный доступ.

## 2. Mac: Git и Python

Среда: Terminal на Mac, произвольный каталог.

Проверьте системные инструменты:

```sh
git --version
/usr/bin/ssh -V
python3 --version
```

Нужен Python 3.12 или новее. Если Git отсутствует, установите Command Line Tools:

```sh
xcode-select --install
```

Дождитесь окончания установки в системном окне. Python можно установить
с [python.org](https://www.python.org/downloads/macos/) либо через Homebrew.
Для варианта Homebrew сначала установите его по инструкции [brew.sh](https://brew.sh/),
после чего выполните:

```sh
brew install python@3.14
```

Для дальнейших команд выберите полный путь интерпретатора. Если ставили через
Homebrew, в этом же терминале:

```sh
SSHIFU_PYTHON="$(brew --prefix python@3.14)/bin/python3.14"
"$SSHIFU_PYTHON" --version
```

Для установщика python.org вместо этого задайте путь к установленному Python,
например `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3`.

```sh
SSHIFU_PYTHON='/Library/Frameworks/Python.framework/Versions/3.14/bin/python3'
"$SSHIFU_PYTHON" --version
```

Если Python уже установлен, подойдет его проверенный полный путь из
`command -v python3`.

## 3. Mac: получить исходники и зависимость

Среда: Terminal на Mac, родительский каталог проектов.

```sh
mkdir -p "$HOME/Documents/dev/projects"
cd "$HOME/Documents/dev/projects"
git clone https://github.com/denzasikora-lab/master-sshifu.git
cd master-sshifu
"$SSHIFU_PYTHON" -m venv .venv
.venv/bin/python --version
.venv/bin/python tools/install_sing_box.py
```

Скрипт сам выбирает arm64 для Apple Silicon или amd64 для Intel. Он скачивает
официальный архив sing-box 1.14.3, проверяет закрепленный SHA256 до распаковки,
извлекает только бинарный файл и проверяет его версию. Результат:
`vendor/sing-box` и локальный `vendor/provenance.json`.

```sh
vendor/sing-box version
```

Ожидается первая строка `sing-box version 1.14.3`. Не запускайте установку
на Mac через sudo: каталог проекта должен принадлежать обычному пользователю.
`pip install` не требуется. Виртуальное окружение изолирует выбранный Python,
внешних Python-библиотек у проекта нет.

Если установщик python.org сообщает об ошибке сертификатов, выполните
`Install Certificates.command` из папки установленного Python в Applications.
Не отключайте проверку TLS. Повторный запуск установщика проверяет уже
установленный бинарный файл и не скачивает его заново без необходимости.

## 4. Mac: отдельный SSH-ключ

Среда: Terminal на Mac, каталог `master-sshifu`. Создайте отдельную пару ключей:

```sh
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -a 64 -N '' -C master-sshifu-client -f "$HOME/.ssh/master-sshifu_ed25519"
chmod 600 "$HOME/.ssh/master-sshifu_ed25519"
chmod 644 "$HOME/.ssh/master-sshifu_ed25519.pub"
```

Если файл уже существует, не подтверждайте перезапись: используйте имеющуюся
отдельную пару или новое имя. Здесь ключ без парольной фразы, чтобы фоновый
SSH с `BatchMode=yes` мог подключаться после обрыва без диалога. Закрытый файл
остается только на Mac. На сервер передается исключительно файл с суффиксом `.pub`.

В консоли провайдера на VPS получите отпечаток ключа сервера:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Сохраните показанный SHA256. На Mac задайте параметры администратора VPS:

```sh
SSHIFU_SERVER='203.0.113.10'
SSHIFU_ADMIN='root'
SSHIFU_PORT=22
```

Если входите через отдельного администратора, измените `SSHIFU_ADMIN`.
Передайте публичный ключ и подключитесь:

```sh
scp -P "$SSHIFU_PORT" "$HOME/.ssh/master-sshifu_ed25519.pub" "$SSHIFU_ADMIN@$SSHIFU_SERVER:master-sshifu-client.pub"
ssh -p "$SSHIFU_PORT" "$SSHIFU_ADMIN@$SSHIFU_SERVER"
```

При первом подключении сверяйте предложенный отпечаток с консолью провайдера,
только после совпадения подтверждайте сохранение. Не используйте
`StrictHostKeyChecking=no`. Не закрывайте административное подключение
до проверки отдельной учетной записи.

## 5. VPS: пакеты и отдельный пользователь

Среда: терминал VPS с Ubuntu/Debian. Если вошли обычным администратором,
сначала получите root через `sudo -i`. Все команды разделов 5-8 выполняются
в этой root-сессии на сервере, а не на Mac.

```sh
apt-get update
apt-get install -y python3 ca-certificates curl git openssh-server
python3 --version
systemctl is-active ssh
adduser --disabled-password --gecos '' sshifu
```

Серверному установщику достаточно системного Python 3.9+. Для работающего
SOCKS-сервера Python вообще не используется: его запускает бинарный sing-box.
Python 3.12+ нужен клиенту и тестам на Mac. Пользователь `sshifu` не получает sudo.
Если эта учетная запись уже существует, проверьте ее назначение и пропустите
создание; не меняйте чужую учетную запись автоматически.

Укажите путь к переданному публичному ключу. При входе администратором root:

```sh
SSHIFU_PUBLIC_KEY='/root/master-sshifu-client.pub'
```

Для администратора с другим домашним каталогом замените путь, например
на `/home/admin/master-sshifu-client.pub`. Проверьте, что это публичный ключ:

```sh
ssh-keygen -lf "$SSHIFU_PUBLIC_KEY"
```

Установите его отдельному пользователю:

```sh
install -d -m 700 -o sshifu -g sshifu /home/sshifu/.ssh
{ printf 'restrict,port-forwarding '; cat "$SSHIFU_PUBLIC_KEY"; } > /home/sshifu/.ssh/authorized_keys
chown sshifu:sshifu /home/sshifu/.ssh/authorized_keys
chmod 600 /home/sshifu/.ssh/authorized_keys
```

Ключ допускает перенаправление портов; функции PTY, агент и X11 ограничены
опцией `restrict`. Непривилегированные команды пользователя остаются доступны
для диагностики и потокового измерителя. Административный ключ не заменяется.

## 6. VPS: установить закрепленный движок

Среда: root-терминал VPS, каталог `/opt`.

```sh
git clone https://github.com/denzasikora-lab/master-sshifu.git /opt/master-sshifu
cd /opt/master-sshifu
python3 tools/install_sing_box.py
/opt/master-sshifu/vendor/sing-box version
chmod 755 /opt/master-sshifu /opt/master-sshifu/vendor
```

Установщик выберет linux-amd64 либо linux-arm64 и выполнит ту же проверку
SHA256. Версия должна быть 1.14.3. Не создавайте новое клонирование поверх
уже работающей установки; порядок обновления описан ниже.

Установите серверную конфигурацию и службу:

```sh
install -d -m 755 /etc/master-sshifu
install -m 644 deploy/server.json /etc/master-sshifu/server.json
install -m 644 deploy/master-sshifu.service /etc/systemd/system/master-sshifu.service
/opt/master-sshifu/vendor/sing-box check -c /etc/master-sshifu/server.json
systemctl daemon-reload
systemctl enable --now master-sshifu.service
```

Служба управляется systemd, но сам процесс работает от `sshifu`, а не от root.
Служба запускается после загрузки VPS и не зависит от открытого SSH-терминала.
Пользовательский linger и cron для этого варианта не нужны.

## 7. VPS: проверить службу и границу доступа

Среда: root-терминал VPS, произвольный каталог.

```sh
systemctl status master-sshifu.service --no-pager
journalctl -u master-sshifu.service -n 50 --no-pager
ss -lntp '( sport = :43190 )'
curl --socks5-hostname 127.0.0.1:43190 --max-time 15 https://api.ipify.org
```

Служба должна быть `active (running)`. В выводе `ss` ожидается исключительно
`127.0.0.1:43190`, не `0.0.0.0:43190` и не `[::]:43190`. Последняя команда
должна вывести публичный IPv4 VPS. Если VPS имеет несколько выходных адресов,
выход должен совпадать с адресом из клиентского `HostName`: это предположение
проверяется кодом. Иной NAT/выход требует отдельной адаптации.

## 8. VPS: проверить политику SSH

Среда: root-терминал VPS.

```sh
/usr/sbin/sshd -T -C user=sshifu,host=localhost,addr=127.0.0.1 | grep -E '^(allowtcpforwarding|disableforwarding|pubkeyauthentication) '
```

Нужны `pubkeyauthentication yes`, `disableforwarding no` и
`allowtcpforwarding yes` либо `local`. Если используются правила по адресу
клиента, вместо 127.0.0.1 укажите настоящий адрес Mac.

Если текущая политика запрещает перенаправление, добавьте отдельный блок
только для `sshifu`. На Ubuntu/Debian с включенным `sshd_config.d`:

```sh
cat > /etc/ssh/sshd_config.d/00-master-sshifu.conf <<'EOF'
# Политика только отдельной учетной записи Master SSHifu.
Match User sshifu
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding no
    AllowTcpForwarding local
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
Match all
EOF
/usr/sbin/sshd -t
```

Только если проверка завершилась успешно, примените конфигурацию:

```sh
systemctl reload ssh
```

Проверьте, что основной `/etc/ssh/sshd_config` действительно содержит Include
для `sshd_config.d`, и повторите `sshd -T -C ...`. Не закрывайте прежнюю
административную сессию до успешного нового подключения. Без необходимости
изменять глобальный SSH или перезапускать VPS не требуется.

## 9. Mac: SSH-профиль

Среда: Terminal на Mac, каталог `master-sshifu`. Серверный терминал можно
оставить открытым отдельно. Откройте `~/.ssh/config` текстовым редактором
и добавьте блок из `deploy/ssh-config.example`. Итоговый пример:

```sshconfig
Host master-sshifu
    HostName 203.0.113.10
    User sshifu
    Port 22
    IdentityFile ~/.ssh/master-sshifu_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    ForwardAgent no
    Compression no
```

Замените IP и при необходимости порт. Для воспроизводимого базового варианта
используйте числовой IPv4 и не добавляйте ProxyJump, ProxyCommand или
RemoteCommand: клиент намеренно их отклоняет.

```sh
chmod 600 "$HOME/.ssh/config"
ssh -T master-sshifu 'id -un'
```

Ожидается `sshifu`. При первом доступе к этому IP/порту ключ сервера должен
быть уже проверен и сохранен на шаге 4. Если возникает ошибка host key,
сначала сверьте отпечаток в консоли провайдера; не удаляйте запись вслепую.

## 10. Mac: физическая сеть и личная конфигурация

Среда: Terminal на Mac, каталог `master-sshifu`. Пока оставьте прежний VPN
в рабочем состоянии, если он нужен для получения зависимостей и связи.

```sh
networksetup -listallhardwareports
route -n get default
```

Найдите физический интерфейс Wi-Fi/Ethernet, например `en0`. Это должен быть
реальный интерфейс сети, не `utun`. Убедитесь, что на нем получены адрес и DNS:

```sh
ipconfig getifaddr en0
ipconfig getoption en0 domain_name_server
```

Если интерфейс другой, замените `en0` в последующих командах.
Если DHCP не сообщает DNS, задайте `dns_direct` вручную в `config.json`
по документации вашей сети; не подставляйте случайный публичный DNS.

```sh
.venv/bin/python tools/configure.py --ssh-alias master-sshifu --interface en0
.venv/bin/python vpn.py check
```

Создается личный `config.json`, исключенный из Git. Пока `backend_ready=false`:
это защита от случайного системного запуска до проверки сервера.

## 11. Mac: пробный SOCKS без изменения маршрутов

Среда: Terminal на Mac, каталог `master-sshifu`.

```sh
.venv/bin/python vpn.py start --mode trial
.venv/bin/python vpn.py check --external
.venv/bin/python vpn.py stop
```

Ожидаются `phase=ready`, внешний IP VPS, завершенная загрузка 1 МиБ и затем
`running=false`. Trial передает TCP через SSH `-D`; пользовательский UDP
в нем отклоняется. Этот тест не меняет системный VPN и не доказывает прямую
связь с VPS вне действующего подключения.

После успешных серверных и клиентских проверок отметьте готовность backend:

```sh
.venv/bin/python tools/configure.py --ssh-alias master-sshifu --interface en0 --backend-ready
```

Эта команда сохраняет отметку, а не проверяет сервер вместо вас.

## 12. Mac: полный транспорт и системный запуск

Среда: Terminal на Mac, каталог `master-sshifu`.

Для постоянного запуска без повторного пароля есть однократная установка
защищенного помощника: [запуск без пароля](PASSWORDLESS.md). После нее вместо
прямой команды sudo используйте `./sshifu`. Сама установка VPN не включает.

При необходимости проверьте отдельный полный SOCKS с UDP-over-TCP:

```sh
.venv/bin/python vpn.py start --mode full
.venv/bin/python vpn.py check --external
.venv/bin/python vpn.py stop
```

Full привязывает SSH и прямой выход к физическому интерфейсу. Он требует
готового серверного SOCKS и не переводит весь Mac на VPN.

Для системного сеанса вручную отключите другой VPN. Запустите одну команду:

```sh
sudo "$PWD/.venv/bin/python" "$PWD/vpn.py" connect
```

Пароль нужен macOS для создания TUN, маршрутов и временного DNS; вводите его
только в терминале. Ожидаются короткие статусы подготовки и включения.
После готовности используйте Mac как обычно. Ввод KEEP не требуется,
начальные веб-пробы не выполняются, предельной длительности сеанса нет.
Терминал остается открытым. Фоновый контроль начинается через 15 секунд.

Если другой VPN занимает основные маршруты, команда сразу уведомляет об этом
и выходит, ничего не отключая и не меняя его DNS. Разные протоколы не устраняют
конфликт маршрутов. Старый `start --mode system` заблокирован; используйте `connect`.

## 13. Приемка на своей сети

Для первого ограниченного испытания вместо постоянного `connect` можно
использовать одну команду при еще включенной Amnezia:

```sh
sudo "$PWD/.venv/bin/python" "$PWD/vpn.py" manual-check --duration 300
```

Этот диагностический режим сначала подготавливает локальный защитник и просит
отключить другой VPN вручную. Сам Amnezia/Happ не отключает. После готовности
проверяет IP и прямой выход, дает 300 секунд на браузерные проверки и
останавливает собственный туннель с откатом. Затем включите прежний VPN сами.
Отчет остается в `/private/var/run/ssh-split-manual-check.json`. Это остановка
своего VPN по таймеру, не автоматический запуск другого клиента.

Среда: Mac, системный сеанс уже показывает «включено».

В другом терминале можно проверить ожидаемый выход VPS:

```sh
curl --noproxy '*' -4fsS --max-time 15 https://api.ipify.org
```

В новой вкладке браузера откройте `https://yandex.ru/internet/`: ожидается
обычный внешний IP провайдера. Откройте YouTube и воспроизводите видео
не меньше 1-2 минут. Затем откройте `https://www.speedtest.net`, нажмите GO
и дождитесь завершения загрузки и отдачи. Ожидается IP VPS, а не провайдера.

Сохраните результаты своей сети. Открытие HTML страницы не подтверждает
видеопоток или завершенный Speedtest. Разные адреса выхода на Яндексе и
сервисе общего IP подтверждают разделение только проверенных запросов.

## 14. Остановка, отчеты и возврат прежнего VPN

В основном терминале нажмите Ctrl+C и дождитесь «выключено». При необходимости
включите прежний VPN вручную. Master SSHifu его автоматически не запускает.

Среда: другой терминал Mac, каталог проекта. Если основной терминал недоступен:

```sh
.venv/bin/python vpn.py stop
.venv/bin/python vpn.py status
cat /private/var/run/ssh-split-session.json
tail -n 30 /private/var/run/ssh-split-session.log
.venv/bin/python vpn.py diagnose
```

Чтение открытых отчетов не требует sudo. Stop подает запрос текущему сеансу,
очистка может еще продолжаться: проверьте итоговое состояние.
При SIGKILL или зависании исполнителя отдельный локальный защитник выполняет
откат; это не зависит от чата. Текущая реализация не является kill switch:
после отката обычный интернет может пойти напрямую.

Если указан конфликт очистки, не удаляйте маршруты другого клиента наугад.
Сохраните отчет, верните рабочий VPN вручную и изучите раздел диагностики.
`diagnose` собирает ограниченные фрагменты журналов в `.runtime` без sudo,
запуска VPN и запросов к интернету. Подробности: [диагностика](TROUBLESHOOTING.md).

## 15. Обновление

На Mac сначала остановите Master SSHifu. Затем в каталоге клона:

```sh
git pull --ff-only
.venv/bin/python tools/install_sing_box.py
.venv/bin/python vpn.py check
```

Если установлен помощник без пароля, после обновления повторите
`sudo .venv/bin/python tools/install_launcher.py`: он обновляет отдельную
системную копию кода и настроек. Сам `git pull` ее не заменяет.

Личный `config.json` не отслеживается Git и сохраняется. При обновлении
закрепленной версии нужен новый проверенный манифест и совместимые настройки.

На VPS в root-сессии:

```sh
systemctl stop master-sshifu.service
cd /opt/master-sshifu
git pull --ff-only
python3 tools/install_sing_box.py
vendor/sing-box check -c /etc/master-sshifu/server.json
systemctl start master-sshifu.service
systemctl status master-sshifu.service --no-pager
```

Измененную вами конфигурацию `/etc/master-sshifu/server.json` обновление Git
не заменяет. Если менялся unit, установите его повторно и выполните daemon-reload.

## 16. Удаление

Mac: сначала Ctrl+C и проверка остановки. Затем удалите каталог клона, если
он больше не нужен. При желании удалите только созданные вами SSH-профиль
и отдельную пару ключей; остальные ключи и known_hosts целиком не удаляйте.

Если использовался запуск без пароля, перед удалением клона выполните
`sudo .venv/bin/python tools/install_launcher.py --remove`.

VPS: root-терминал, каталог произвольный:

```sh
systemctl disable --now master-sshifu.service
rm /etc/systemd/system/master-sshifu.service
systemctl daemon-reload
```

После проверки, что эти каталоги принадлежат только проекту, можно удалить
`/opt/master-sshifu` и `/etc/master-sshifu`. Учетную запись и ее authorized_keys
удаляйте только если она создана исключительно для этого проекта.
Если добавляли отдельный SSH-блок, удалите именно его, проверьте `sshd -t`
и только после успешной проверки выполните reload. Другие настройки не меняйте.
