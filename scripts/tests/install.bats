#!/usr/bin/env bats
# White-box тесты install.sh: sandbox FT_PREFIX/FT_WG_DIR, без root, wg застаблен.

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/../install.sh"
    export FT_PREFIX="$BATS_TEST_TMPDIR/prefix"
    export FT_WG_DIR="$BATS_TEST_TMPDIR/wg"
    mkdir -p "$FT_PREFIX" "$FT_WG_DIR"
    # shellcheck disable=SC1090
    source "$SCRIPT"
    set +e
    trap - EXIT
    PUBLIC_HOST="203.0.113.7"
    wg_up() { return 1; }
    wg() {
        case "$1" in
            genkey) printf 'priv%04d%s=\n' "$RANDOM" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | cut -c1-44 ;;
            pubkey) local k; read -r k; printf 'pub-%s\n' "${k:4:39}" ;;
        esac
    }
}

decode_uri() {
    local b=${1#freeturn://}
    b=$(printf '%s' "$b" | tr -- '-_' '+/')
    while [ $(( ${#b} % 4 )) -ne 0 ]; do b="$b="; done
    printf '%s' "$b" | base64 -d
}

need_jq() { command -v jq >/dev/null 2>&1 || skip "нет jq"; }

@test "valid_port" {
    valid_port 1
    valid_port 65535
    ! valid_port 0
    ! valid_port 65536
    ! valid_port 080
    ! valid_port "1 2"
}

@test "valid_hostport: v4, имя, [v6]; без скобок v6 нельзя" {
    valid_hostport 127.0.0.1:51820
    valid_hostport vpn.example.com:443
    valid_hostport '[2001:db8::1]:51820'
    ! valid_hostport '2001:db8::1:51820'
    ! valid_hostport 'a;b:1'
    ! valid_hostport 'host:70000'
    ! valid_hostport 'host'
}

@test "valid_net: сетевой адрес, префикс 16..29" {
    valid_net 10.13.13.0/24
    valid_net 172.20.0.0/16
    ! valid_net 10.13.13.1/24
    ! valid_net 10.13.13.0/30
    ! valid_net 10.13.13.0/8
    ! valid_net 10.13.256.0/24
    ! valid_net 010.13.13.0/24
}

@test "valid_name и valid_version" {
    valid_name owner
    valid_name phone-1.a_b
    ! valid_name ../x
    ! valid_name .hidden
    ! valid_name "a b"
    valid_version latest
    valid_version v3.5.0
    valid_version v3.5.0-rc.1
    ! valid_version 3.5.0
}

@test "valid_kcp: токены argv" {
    valid_kcp ""
    valid_kcp "-kcp-nodelay 1 -kcp-mtu 1200 -kcp-acknodelay=true"
    ! valid_kcp "-kcp-nodelay x"
    ! valid_kcp "-kcp-foo 1"
    ! valid_kcp '-kcp-nodelay 1; rm -rf /'
}

@test "ip2int/int2ip и пересечение подсетей" {
    [ "$(int2ip "$(ip2int 10.13.13.254)")" = 10.13.13.254 ]
    nets_overlap 10.13.13.0/24 10.13.0.0/16
    nets_overlap 10.13.13.0/24 10.13.13.5/32
    ! nets_overlap 10.13.13.0/24 10.13.14.0/24
}

@test "join_hostport: скобки для v6" {
    [ "$(join_hostport 1.2.3.4 56000)" = 1.2.3.4:56000 ]
    [ "$(join_hostport 2001:db8::1 56000)" = '[2001:db8::1]:56000' ]
}

@test "parse_opts: kcp заменяет набор целиком, ошибки -> bad_arg" {
    KCP_ARGS="-kcp-mtu 1000"
    parse_opts --kcp-nodelay=1 --kcp-acknodelay=true
    [ "$KCP_ARGS" = "-kcp-nodelay 1 -kcp-acknodelay=true" ]
    valid_kcp "$KCP_ARGS"
    _IS_RPC=1
    run parse_opts --connect='x;y:1'
    [[ "$output" == *'"code":"bad_arg"'* ]]
    run parse_opts --bogus
    [[ "$output" == *'"code":"bad_arg"'* ]]
}

@test "server_argv: new -> свой WG, obf, clients-file" {
    BACKEND=new WG_PORT=51999 LISTEN_PORT=56001 OBF_PROFILE=rtpopus3 OBF_KEY=abc
    run server_argv
    [ "${lines[0]}" = -listen ] && [ "${lines[1]}" = 0.0.0.0:56001 ]
    [ "${lines[3]}" = 127.0.0.1:51999 ]
    [[ "$output" == *$'-clients-file\n'"$CLIENTSFILE"* ]]
    [[ "$output" == *$'-obf-profile\nrtpopus3\n-obf-key\nabc'* ]]
}

@test "server_argv: external tcp + kcp, obf none" {
    BACKEND=external CONNECT=127.0.0.1:443 PROXY_MODE=tcp OBF_PROFILE=none KCP_ARGS="-kcp-mtu 1200"
    run server_argv
    [ "${lines[3]}" = 127.0.0.1:443 ]
    [[ "$output" != *obf* ]]
    [ "${lines[-2]}" = -kcp-mtu ] && [ "${lines[-1]}" = 1200 ]
    PROXY_MODE=udp
    run server_argv
    [[ "$output" != *kcp* ]]
}

@test "validate_config: tcp со своим WG запрещён, ключ генерится" {
    _IS_RPC=1
    BACKEND=new PROXY_MODE=tcp
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
    PROXY_MODE=udp OBF_KEY=""
    validate_config
    valid_hex64 "$OBF_KEY"
    OBF_PROFILE=none
    validate_config
    [ -z "$OBF_KEY" ]
}

@test "validate_config: external без connect -> bad_arg" {
    _IS_RPC=1
    BACKEND=external CONNECT=""
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
}

@test "save_config/load_config: круг и отпечаток ссылок" {
    BACKEND=external CONNECT=10.0.0.2:443 PROXY_MODE=tcp KCP_ARGS="-kcp-mtu 1200"
    save_config
    BACKEND=new CONNECT="" KCP_ARGS=""
    load_config
    [ "$BACKEND" = external ] && [ "$CONNECT" = 10.0.0.2:443 ] && [ "$KCP_ARGS" = "-kcp-mtu 1200" ]
    [ "$PREV_SHARE" = "$(share_fingerprint)" ]
    [ "$PREV_LISTEN_PORT" = "$LISTEN_PORT" ]
}

@test "meta_put/meta_get/meta_del: замена на месте" {
    meta_put "a|1|||"
    meta_put "b|2|||"
    meta_put "a|9|||"
    [ "$(head -n1 "$CLIENTS_META")" = "a|9|||" ]
    [ "$(wc -l < "$CLIENTS_META")" -eq 2 ]
    meta_del a
    ! meta_has a
    meta_has b
}

@test "freeturn_uri: схема internal/uri" {
    OBF_PROFILE=rtpopus3 OBF_KEY=$(printf 'a%.0s' {1..64}) PROXY_MODE=tcp LISTEN_PORT=56000
    json=$(decode_uri "$(freeturn_uri cid123 phone $'[Interface]\nA = 1')")
    [[ "$json" == '{"v":1,"provider":"vk","peer":"203.0.113.7:56000","mode":"tcp","obf":"rtpopus3"'* ]]
    [[ "$json" == *'"cid":"cid123","name":"phone","wg":"[Interface]\nA = 1"}' ]]
    OBF_PROFILE=none PROXY_MODE=udp
    json=$(decode_uri "$(freeturn_uri c n "")")
    [[ "$json" != *obf* && "$json" != *mode* && "$json" != *wg* ]]
}

@test "wg: конфиг, выдача адресов, вырез пира" {
    WG_NET=10.13.13.0/24 WG_PORT=51820
    wg_write_conf
    wg_ours
    [ "$(wg_conf_net)" = 10.13.13.0/24 ]
    grep -q '^Address = 10.13.13.1/24$' "$WG_CONF"
    grep -q '^PostUp = iptables -t nat -A POSTROUTING -s 10.13.13.0/24 ! -d 10.13.13.0/24 -j MASQUERADE$' "$WG_CONF"
    mkdir -p "$(client_dir a)" "$(client_dir b)"
    wg_peer_add a
    [ "$PEER_IP" = 10.13.13.2 ]
    wg_peer_add b
    [ "$PEER_IP" = 10.13.13.3 ]
    grep -q '^Endpoint = 127.0.0.1:9000$' "$(client_conf_file b)"
    grep -q '^MTU = 1280$' "$(client_conf_file b)"
    wg_peer_remove a
    ! grep -q 'ft-client: a$' "$WG_CONF"
    grep -q 'ft-client: b$' "$WG_CONF"
    [ "$(wg_next_ip)" = 10.13.13.2 ]
}

@test "wg_next_ip: подсеть кончилась" {
    WG_NET=10.13.13.0/29
    wg_write_conf
    for i in 2 3 4 5 6; do printf '[Peer]\nAllowedIPs = 10.13.13.%s/32\n' "$i" >> "$WG_CONF"; done
    ! wg_next_ip
}

@test "wg_apply: чужой ft-wg0.conf не трогаем" {
    _IS_RPC=1
    has_systemd() { return 0; }
    wg_tools_ensure() { :; }
    printf '[Interface]\nAddress = 10.0.0.1/24\n' > "$WG_CONF"
    run wg_apply
    [[ "$output" == *'"code":"wg_conflict"'* ]]
}

@test "клиенты: external - только client_id, хозяина не удалить" {
    need_jq
    BACKEND=external
    auth_init
    clients_sync
    meta_has owner
    cid=$(meta_get owner | cut -d'|' -f2)
    [[ "$cid" =~ ^[0-9a-f]{32}$ ]]
    [ "$(jq -r --arg id "$cid" '.clients[$id].comment' "$CLIENTSFILE")" = owner ]
    [ -s "$(client_dir owner)/owner.link" ]
    [ ! -f "$(client_conf_file owner)" ]
    client_create phone
    _IS_RPC=1
    run client_create phone
    [[ "$output" == *'"code":"exists"'* ]]
    run client_delete owner
    [[ "$output" == *'"code":"owner_protected"'* ]]
    run client_delete nobody
    [[ "$output" == *'"code":"not_found"'* ]]
    pcid=$(meta_get phone | cut -d'|' -f2)
    client_delete phone
    ! meta_has phone
    [ "$(jq -r --arg id "$pcid" '.clients[$id] // "gone"' "$CLIENTSFILE")" = gone ]
    [ ! -d "$(client_dir phone)" ]
}

@test "клиенты: переход external -> new даёт пиры всем, снос WG их убирает" {
    need_jq
    BACKEND=external
    auth_init
    clients_sync
    client_create phone
    BACKEND=new WG_NET=10.13.13.0/24
    wg_write_conf
    clients_sync
    [ "$(meta_get owner | cut -d'|' -f3)" = 10.13.13.2 ]
    [ "$(meta_get phone | cut -d'|' -f3)" = 10.13.13.3 ]
    [ -f "$(client_conf_file phone)" ]
    json=$(decode_uri "$(cat "$(client_dir phone)/phone.link")")
    [[ "$json" == *'"wg":"[Interface]'* ]]
    clients_drop_peers
    [ -z "$(meta_get phone | cut -d'|' -f3)" ]
    [ ! -f "$(client_conf_file phone)" ]
    json=$(decode_uri "$(cat "$(client_dir phone)/phone.link")")
    [[ "$json" != *'"wg"'* ]]
}

@test "rpc client-list / client-conf: JSON" {
    need_jq
    BACKEND=external CONNECT=127.0.0.1:443 OBF_PROFILE=none
    save_config
    auth_init
    clients_sync
    run bash "$SCRIPT" client-list
    [ "$(jq -r .result <<< "$output")" = ok ]
    [ "$(jq -r '.data.clients[0].name' <<< "$output")" = owner ]
    [ "$(jq -r '.data.clients[0].self' <<< "$output")" = true ]
    [ "$(jq -r '.data.share.host' <<< "$output")" = 203.0.113.7 ]
    [ "$(jq -r '.data.share.backend' <<< "$output")" = external ]
    run bash "$SCRIPT" client-conf --name=owner
    [[ "$(jq -r .data.link <<< "$output")" == freeturn://* ]]
    run bash "$SCRIPT" client-conf --name=ghost
    [ "$(jq -r .code <<< "$output")" = not_found ]
}

@test "rpc probe: без install.conf нет config" {
    run bash "$SCRIPT" probe
    [[ "$output" == '{"proto":3,"result":"ok"'* ]]
    [[ "$output" != *'"config"'* ]]
}

@test "rpc: мутирующие команды без root -> needs_root" {
    [ "$(id -u)" -ne 0 ] || skip "запущено от root"
    for c in apply client-add uninstall stop restart; do
        run bash "$SCRIPT" "$c" --name=x
        [[ "$output" == *'"code":"needs_root"'* ]] || [[ "$output" == *'"code":"not_installed"'* ]]
    done
}

@test "validate_config: web-port и web-ttl" {
    _IS_RPC=1
    BACKEND=external CONNECT=127.0.0.1:443
    FT_WEB_PORT=99999
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
    FT_WEB_PORT=8080 FT_WEB_TTL=10
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
}

@test "version=local: держится без --bin, --update возвращает на релиз, не-ELF отбит" {
    _IS_RPC=1
    BACKEND=external CONNECT=127.0.0.1:443 VERSION=local
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
    printf '#!/bin/sh\n' > "$BIN"; chmod +x "$BIN"
    validate_config
    [ "$VERSION" = local ]
    FORCE_UPDATE=1
    validate_config
    [ "$VERSION" = latest ]

    parse_opts --bin="$BATS_TEST_TMPDIR/up"
    [ "$VERSION" = local ]
    run validate_config
    [[ "$output" == *'"code":"bad_arg"'* ]]
    echo junk > "$LOCAL_BIN"
    run binary_local
    [[ "$output" == *'не ELF'* ]]
    printf '\177ELF....' > "$LOCAL_BIN"
    binary_local
    [ "$(cat "$VERFILE")" = local ] && [ -x "$BIN" ] && [ ! -e "$LOCAL_BIN" ]
    [ "$(image_tag)" = latest ]
}

@test "диспетчер: CLI-флаги не RPC, все RPC-команды опознаются" {
    for f in -y --yes --update --uninstall --reconfigure --purge client ""; do
        ! is_rpc_command "$f"
    done
    for c in $RPC_COMMANDS; do
        is_rpc_command "$c"
        declare -F "cmd_${c//-/_}" >/dev/null
    done
}

@test "web_token стабилен, client_token свой у каждого клиента" {
    t1=$(web_token); t2=$(web_token)
    [ "$t1" = "$t2" ] && [ "${#t1}" -eq 32 ] && [ -f "$WEB_TOKEN_FILE" ]
    a=$(client_token phone); b=$(client_token laptop)
    [ "$a" = "$(client_token phone)" ] && [ "$a" != "$b" ] && [ "$a" != "$t1" ] && [ "${#a}" -eq 32 ]
    WEB_TOKEN_FILE=/proc/nonexistent/web.token
    ! web_token
}

@test "_web_layout: каталог клиента только за его токеном, удалённый убирается" {
    mkdir -p "$(client_dir phone)" "$(client_dir laptop)"
    printf 'phone|a|||now\nlaptop|b|||now\n' > "$CLIENTS_META"
    _web_layout
    [ -f "$WEB_ROOT/index.html" ] && [ -f "$WEB_ROOT/$(web_token)$WEB_PROBE_EXT" ]
    [ "$(readlink "$WEB_ROOT/$(client_token phone)")" = "$(client_dir phone)" ]
    [ ! -L "$WEB_ROOT/$(web_token)" ]
    gone=$(client_token laptop)
    printf 'phone|a|||now\n' > "$CLIENTS_META"
    rm -rf "$(client_dir laptop)"
    _web_layout
    [ ! -L "$WEB_ROOT/$gone" ]
}

@test "ensure_web_server: порт открывает сам и закрывает при неудаче" {
    fw="$BATS_TEST_TMPDIR/fw.log"
    firewall_open_port()  { echo "open $1/$2" >> "$fw"; }
    firewall_close_port() { echo "close $1/$2" >> "$fw"; }
    _web_listening() { return 1; }
    _web_systemd_active() { return 1; }
    _web_server_argv() { printf '%s\n' fake-httpd "$1"; }
    _web_start_systemd() { return 1; }
    _web_start_nohup() { return 1; }
    ss() { :; }
    ! ensure_web_server
    grep -q 'open 8080/tcp' "$fw"
    grep -q 'close 8080/tcp' "$fw"
}

@test "_web_server_argv: python3, иначе busybox" {
    HAVE=""
    command() {
        if [ "$1" = -v ]; then
            case " $HAVE " in *" $2 "*) echo "/usr/bin/$2"; return 0 ;; esac
            return 1
        fi
        builtin command "$@"
    }
    pkg_install() { return 1; }
    ! _web_server_argv 8080
    HAVE=busybox
    [ "$(_web_server_argv 8080 | tr '\n' ' ')" = "busybox httpd -f -p 8080 -h $WEB_ROOT " ]
    HAVE="python3 busybox"
    [ "$(_web_server_argv 8080 | tr '\n' ' ')" = "python3 -m http.server 8080 --directory $WEB_ROOT " ]
}

@test "get_public_ip: ошибка вместо плейсхолдера" {
    curl() { return 1; }
    ! get_public_ip
}

@test "client_delete убирает веб-симлинк клиента" {
    need_jq
    BACKEND=external
    auth_init
    clients_sync
    client_create phone
    _web_layout
    tok=$(client_token phone)
    [ -L "$WEB_ROOT/$tok" ]
    client_delete phone
    [ ! -L "$WEB_ROOT/$tok" ]
}

legacy_fixture() {
    # Старый install.conf формата v4 (GitHub): без BACKEND=, с CLIENTS_FILE_CONF.
    cat > "$CONF_FILE" <<EOF
VERSION="latest"
PROVIDER="vk"
PROXY_MODE="udp"
BACKEND_PORT="51820"
LISTEN_PORT="56001"
OBF_PROFILE="rtpopus"
OBF_KEY="$(printf 'a%.0s' {1..64})"
CLIENTS_FILE_CONF="$FT_PREFIX/clients/clients.json"
WG_SETUP="1"
WG_ENDPOINT="127.0.0.1:9000"
EOF
    mkdir -p "$FT_PREFIX/clients"
    cat > "$FT_PREFIX/clients/clients.json" <<'EOF'
{"clients":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"comment":"owner"},"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"comment":"phone"}}}
EOF
    mkdir -p "$FT_WG_DIR"
    cat > "$FT_WG_DIR/wg0.conf" <<'EOF'
[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = cHJpdmF0ZWtleXRlc3RrZXkxMjM0NTY3ODkwYWJjZA==

[Peer]
PublicKey = cHVibGlja2V5b3duZXJ0ZXN0a2V5MTIzNDU2Nzg5MGFiYw==
AllowedIPs = 10.13.13.2/32

[Peer]
PublicKey = cHVibGlja2V5cGhvbmV0ZXN0a2V5MTIzNDU2Nzg5MGFiZGVm
AllowedIPs = 10.13.13.3/32
EOF
    # shellcheck disable=SC1090
    . "$CONF_FILE"
}

@test "migrate: legacy_detect отличает старый конфиг от нового" {
    legacy_fixture
    legacy_detect
    BACKEND=new CONNECT="" PUBLIC_HOST=203.0.113.7 PROXY_MODE=udp \
        LISTEN_PORT=56001 WG_PORT=51820 WG_NET=10.13.13.0/24 \
        OBF_PROFILE=rtpopus3 OBF_KEY=x VERSION=latest save_config
    ! legacy_detect
}

@test "migrate: legacy_read маппит v4->v5 (rtpopus->rtpopus3, тот же ключ)" {
    need_jq
    legacy_fixture
    LEGACY_WG_CONF="$FT_WG_DIR/wg0.conf"
    legacy_read
    [ "$BACKEND" = new ]
    [ "$PROXY_MODE" = udp ]
    [ "$OBF_PROFILE" = rtpopus3 ]
    [ "$OBF_KEY" = "$(printf 'a%.0s' {1..64})" ]
    [ "$MIGRATE_OBF_REUSED" = 1 ]
    [ "$MIGRATE_MODE_CHANGED" = 0 ]
    [ "$WG_NET" = 10.13.13.0/24 ]
    [ "$VERSION" = latest ]
    [ "$LEGACY_CLIENTS" = 2 ]
    [ "$LEGACY_PEERS" = 2 ]
}

@test "migrate: legacy_read tcp+new едет в udp, external сохраняет connect" {
    legacy_fixture
    LEGACY_WG_CONF="$FT_WG_DIR/wg0.conf"
    PROXY_MODE=tcp
    legacy_read
    [ "$PROXY_MODE" = udp ]
    [ "$MIGRATE_MODE_CHANGED" = 1 ]
    rm -f "$FT_WG_DIR/wg0.conf" "$LEGACY_WG_CONF_FALLBACK"
    LEGACY_WG_CONF=/proc/nonexistent/wg0.conf
    cat > "$CONF_FILE" <<EOF
VERSION="latest"
PROVIDER="vk"
PROXY_MODE="tcp"
BACKEND_PORT="443"
LISTEN_PORT="56001"
OBF_PROFILE="none"
CLIENTS_FILE_CONF=""
WG_SETUP="0"
EOF
    # shellcheck disable=SC1090
    . "$CONF_FILE"
    legacy_read
    [ "$BACKEND" = external ]
    [ "$CONNECT" = 127.0.0.1:443 ]
    [ "$PROXY_MODE" = tcp ]
    [ "$MIGRATE_MODE_CHANGED" = 0 ]
    [ "$MIGRATE_AUTH_WAS_OFF" = 1 ]
}

@test "migrate: dry-run отдаёт маппинг без изменений" {
    need_jq
    legacy_fixture
    LEGACY_WG_CONF="$FT_WG_DIR/wg0.conf"
    require_root() { return 0; }
    ensure_base_deps() { return 0; }
    _IS_RPC=1
    out=$(DRY_RUN=1 cmd_migrate)
    [ "$(jq -r .result <<< "$out")" = ok ]
    [ "$(jq -r .data.backend <<< "$out")" = new ]
    [ "$(jq -r .data.obf_profile <<< "$out")" = rtpopus3 ]
    [ "$(jq -r .data.obf_key_reused <<< "$out")" = true ]
    [ "$(jq -r .data.legacy_clients <<< "$out")" = 2 ]
    # dry-run ничего не пишет: нового конфига и ft-wg0 нет
    ! grep -q '^BACKEND=' "$CONF_FILE"
    [ ! -f "$WG_CONF" ]
}

@test "migrate: повтор на новом формате -> already_migrated" {
    need_jq
    require_root() { return 0; }
    ensure_base_deps() { return 0; }
    _IS_RPC=1
    BACKEND=new CONNECT="" PUBLIC_HOST=203.0.113.7 PROXY_MODE=udp \
        LISTEN_PORT=56000 WG_PORT=51820 WG_NET=10.13.13.0/24 \
        OBF_PROFILE=rtpopus3 OBF_KEY="$(printf 'b%.0s' {1..64})" VERSION=latest save_config
    out=$(cmd_migrate)
    [ "$(jq -r .data.reason <<< "$out")" = already_migrated ]
}

@test "migrate: чистый хост -> not_installed, а не already_migrated" {
    require_root() { return 0; }
    ensure_base_deps() { return 0; }
    _IS_RPC=1
    run cmd_migrate
    [ "$status" -eq 1 ]
    [[ "$output" == *'"code":"not_installed"'* ]]
}

@test "migrate: import пиров сохраняет client_id и IP из wg0" {
    need_jq
    legacy_fixture
    LEGACY_WG_CONF="$FT_WG_DIR/wg0.conf"
    legacy_read
    BACKEND=new WG_NET=10.13.13.0/24 PUBLIC_HOST=203.0.113.7
    auth_init
    wg_write_conf
    # Порядок как в cmd_migrate: сначала apply/clients_sync (свежий хозяин)...
    clients_sync
    fresh_owner_cid=$(meta_get owner | cut -d'|' -f2)
    # ...затем импорт legacy поверх: свежий cid хозяина вытесняется старым.
    migrate_import_peers "$FT_WG_DIR/wg0.conf" "$FT_PREFIX/clients/clients.json"
    # Те же client_id, те же IP, имена из comment; дублей нет.
    [ "$(meta_get owner | cut -d'|' -f2)" = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]
    [ "$fresh_owner_cid" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]
    [ "$(meta_get owner | cut -d'|' -f3)" = 10.13.13.2 ]
    [ "$(meta_get phone | cut -d'|' -f2)" = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]
    [ "$(meta_get phone | cut -d'|' -f3)" = 10.13.13.3 ]
    [ "$(grep -c '^owner|' "$CLIENTS_META")" = 1 ]
    [ "$(jq -r '.clients | length' "$CLIENTSFILE")" = 2 ]
    [ "$(jq -r --arg id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '.clients[$id].comment' "$CLIENTSFILE")" = owner ]
    grep -q 'AllowedIPs = 10.13.13.2/32' "$WG_CONF"
    grep -q 'AllowedIPs = 10.13.13.3/32' "$WG_CONF"
    # Конфиг клиента перевыпущен, ссылки пересобраны под новый профиль/ключ.
    [ -f "$(client_conf_file phone)" ]
    json=$(decode_uri "$(cat "$(client_dir phone)/phone.link")")
    [[ "$json" == *'"obf":"rtpopus3"'* ]]
    [[ "$json" == *'"cid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'* ]]
    [[ "$json" == *'"wg":"[Interface]'* ]]
}

@test "migrate: cleanup сносит compose/wireguard-client/старый allowlist, новый не трогает" {
    need_jq
    legacy_fixture
    LEGACY_WG_CONF="$FT_WG_DIR/wg0.conf"
    legacy_read
    auth_init
    printf 'image: ghcr.io/old OBF_KEY=secret\n' > "$FT_PREFIX/docker-compose.yml"
    printf '[Interface]\n' > "$FT_PREFIX/wireguard-client.conf"
    migrate_cleanup_legacy
    [ ! -f "$FT_PREFIX/docker-compose.yml" ]
    [ ! -f "$FT_PREFIX/wireguard-client.conf" ]
    [ ! -f "$FT_PREFIX/clients/clients.json" ]
    # Новый allowlist на месте (бэкап тоже снят, но tar может отсутствовать в CI).
    [ -f "$CLIENTSFILE" ]
}

@test "диспетчер знает migrate" {
    is_rpc_command migrate
    declare -F cmd_migrate >/dev/null
}

control_fixture() {
    # Поколение free-turn-control.sh: install.conf нет, есть launch.sh/run.args.
    rm -f "$CONF_FILE"
    cat > "$PREFIX/run.args" <<EOF
-listen
0.0.0.0:56016
-connect
127.0.0.1:51554
-mode
udp
-obf-profile
rtpopus
-obf-key
$(printf 'b%.0s' {1..64})
-clients-file
$PREFIX/clients.json
EOF
    printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' > "$PREFIX/owner.cid"
    printf 'v1.8.0\n' > "$PREFIX/version"
    printf '#!/bin/bash\n' > "$PREFIX/launch.sh"
    cat > "$PREFIX/clients.json" <<'EOF'
{"clients":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"comment":"owner"},"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"comment":"phone"}}}
EOF
    cat > "$WG_CONF" <<'EOF'
[Interface]
# managed-by: free-turn-proxy
Address = 10.13.13.1/24
ListenPort = 51554
MTU = 1280
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LXRlc3QtZml4dHVyZS0wMTIzNA==

[Peer]
# owner (client conf: /opt/free-turn-proxy/wireguard-client.conf)
PublicKey = c2VydmVyLXB1YmxpYy1rZXktdGVzdC1maXh0dXJlLTAxMjM0NQ==
AllowedIPs = 10.13.13.2/32

[Peer]
# ft-user: cGhvbmU=
PublicKey = Y2xpZW50LXB1YmxpYy1rZXktdGVzdC1maXh0dXJlLWFiY2RlZg==
AllowedIPs = 10.13.13.3/32
EOF
}

@test "migrate: detect_kind различает v5/v1/control/none" {
    [ "$(detect_kind)" = none ]
    legacy_fixture
    [ "$(detect_kind)" = v1 ]
    BACKEND=new CONNECT="" PUBLIC_HOST=203.0.113.7 PROXY_MODE=udp \
        LISTEN_PORT=56000 WG_PORT=51820 WG_NET=10.13.13.0/24 \
        OBF_PROFILE=rtpopus3 OBF_KEY=x VERSION=latest save_config
    [ "$(detect_kind)" = v5 ]
    rm -f "$CONF_FILE"
    printf '#!/bin/bash\n' > "$PREFIX/launch.sh"
    [ "$(detect_kind)" = control ]
}

@test "migrate: control_read_runargs парсит argv построчно и -k=v" {
    cat > "$PREFIX/run.args" <<'EOF'
-listen
0.0.0.0:56016
-connect=127.0.0.1:51554
-mode
udp
-obf-profile
rtpopus
-obf-key
abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
-clients-file
/tmp/x/clients.json
EOF
    control_read_runargs
    [ "$CTRL_LISTEN" = 0.0.0.0:56016 ]
    [ "$CTRL_CONNECT" = 127.0.0.1:51554 ]
    [ "$CTRL_MODE" = udp ]
    [ "$CTRL_OBF" = rtpopus ]
    [ "$CTRL_KEY" = abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 ]
    [ "$CTRL_CLIENTSFILE" = /tmp/x/clients.json ]
}

@test "migrate: control_read маппит control-поколение из живых файлов" {
    need_jq
    control_fixture
    control_read
    [ "$BACKEND" = new ]
    [ "$PROXY_MODE" = udp ]
    [ "$LISTEN_PORT" = 56016 ]
    [ "$WG_PORT" = 51554 ]
    [ "$WG_NET" = 10.13.13.0/24 ]
    [ "$OBF_PROFILE" = rtpopus3 ]
    [ "$OBF_KEY" = "$(printf 'b%.0s' {1..64})" ]
    [ "$MIGRATE_OBF_REUSED" = 1 ]
    [ "$MIGRATE_MODE_CHANGED" = 0 ]
    [ "$LEGACY_CLIENTS" = 2 ]
    [ "$LEGACY_PEERS" = 2 ]
    [ "$LEGACY_VERSION" = v1.8.0 ]
    [ "$MIGRATE_FRESH_IPS" = 1 ]
    [ "$VERSION" = latest ]
}

@test "migrate: явные CLI-флаги побеждают детект" {
    need_jq
    control_fixture
    parse_opts --listen-port=56099 --obf-profile=none
    control_read
    [ "$LISTEN_PORT" = 56099 ]
    [ "$OBF_PROFILE" = none ]
    [ "$OBF_KEY" = "" ]
    [ "$BACKEND" = new ]
}

@test "migrate: control dry-run показывает kind и версию поколения" {
    need_jq
    control_fixture
    require_root() { return 0; }
    ensure_base_deps() { return 0; }
    _IS_RPC=1
    out=$(DRY_RUN=1 cmd_migrate)
    [ "$(jq -r .result <<< "$out")" = ok ]
    [ "$(jq -r .data.kind <<< "$out")" = control ]
    [ "$(jq -r .data.legacy_version <<< "$out")" = v1.8.0 ]
    [ "$(jq -r .data.listen_port <<< "$out")" = 56016 ]
    [ "$(jq -r .data.legacy_clients <<< "$out")" = 2 ]
}

@test "migrate: import control сохраняет старые блоки и выдаёт свежие IP" {
    need_jq
    control_fixture
    control_read
    BACKEND=new WG_NET=10.13.13.0/24 PUBLIC_HOST=203.0.113.7
    auth_init
    clients_sync
    migrate_import_peers "$WG_CONF" "$PREFIX/clients.json"
    # legacy cid вытеснили свежие; IP новые (.2/.3 заняты старыми блоками)
    [ "$(meta_get owner | cut -d'|' -f2)" = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]
    [ "$(meta_get phone | cut -d'|' -f2)" = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]
    [ "$(meta_get owner | cut -d'|' -f3)" = 10.13.13.4 ]
    [ "$(meta_get phone | cut -d'|' -f3)" = 10.13.13.5 ]
    [ "$(jq -r '.clients | length' "$CLIENTSFILE")" = 2 ]
    # старые блоки на месте (старые конфиги продолжают работать)
    grep -q '# ft-user: cGhvbmU=' "$WG_CONF"
    grep -q 'AllowedIPs = 10.13.13.3/32' "$WG_CONF"
    grep -q 'PrivateKey = c2VydmVyLXByaXZhdGUta2V5LXRlc3QtZml4dHVyZS0wMTIzNA==' "$WG_CONF"
    # новые блоки рядом, конфиги для расшаривания есть
    grep -q '# ft-client: phone' "$WG_CONF"
    [ -f "$(client_conf_file phone)" ]
    json=$(decode_uri "$(cat "$(client_dir phone)/phone.link")")
    [[ "$json" == *'"obf":"rtpopus3"'* ]]
    [[ "$json" == *'"cid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"'* ]]
}

@test "migrate: cleanup сносит артефакты control-поколения" {
    control_fixture
    printf '#!/bin/bash\n' > "$PREFIX/launch.sh"
    printf 'x\n' > "$PREFIX/run.env"
    printf 'v1.8.0\n' > "$PREFIX/state"
    : > "$PREFIX/control.lock"
    printf '[Interface]\n' > "$PREFIX/wireguard-client.conf"
    printf 'ELF' > "$PREFIX/server-linux-amd64"
    mkdir -p "$PREFIX/share"
    MIGRATE_KIND=control
    LEGACY_CLIENTS_FILE="$PREFIX/clients.json"
    auth_init
    migrate_cleanup_legacy
    for f in launch.sh run.args run.env owner.cid version state control.lock wireguard-client.conf server-linux-amd64 clients.json; do
        [ ! -e "$PREFIX/$f" ] || return 1
    done
    [ ! -d "$PREFIX/share" ]
    # усыновлённый WG-конф и новый allowlist целы
    grep -q '# ft-user: cGhvbmU=' "$WG_CONF"
    [ -f "$CLIENTSFILE" ]
}

@test "step: при сбое называет шаг и показывает последние 20 строк" {
    export TMPDIR="$BATS_TEST_TMPDIR"
    _IS_RPC=0; HAS_GUM=0
    run step "Тестовый шаг" bash -c 'for i in $(seq 1 30); do echo "строка-$i"; done; exit 3'
    [ "$status" -eq 3 ]
    [[ "$output" == *"Шаг «Тестовый шаг» не удался (код 3)"* ]]
    [[ "$output" == *"строка-30"* ]]
    [[ "$output" == *"строка-11"* ]]
    [[ "$output" != *"строка-10"* ]]
}

@test "_install_docker не запускает sh, если скачивание не удалось" {
    _dl() { return 22; }
    sh() { touch "$BATS_TEST_TMPDIR/sh-called"; }
    run _install_docker
    [ "$status" -eq 22 ]
    [ ! -e "$BATS_TEST_TMPDIR/sh-called" ]
}

@test "_install_docker запускает скачанный скрипт" {
    _dl() { echo x >"$2"; }
    sh() { touch "$BATS_TEST_TMPDIR/sh-called"; }
    run _install_docker
    [ "$status" -eq 0 ]
    [ -e "$BATS_TEST_TMPDIR/sh-called" ]
}

@test "неожиданный выход в обычном режиме называет этап" {
    export TMPDIR="$BATS_TEST_TMPDIR"
    run bash -c 'source "$1"; _IS_RPC=0; HAS_GUM=0; _STAGE="Загрузка образа"; false' _ "$SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Установка прервана на этапе «Загрузка образа»"* ]]
}

@test "with_lock не глушит stderr навсегда" {
    command -v flock >/dev/null 2>&1 || skip "нет flock"
    run bash -c 'source "$1"; with_lock; echo err-visible >&2' _ "$SCRIPT"
    [[ "$output" == *"err-visible"* ]]
}
