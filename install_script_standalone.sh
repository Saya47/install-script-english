#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# System Required: CentOS 7+/Ubuntu 18+/Debian 10+
# Version: v2.0.4
# Description: One click Install Trojan Panel standalone server
# Author: jonssonyan <https://jonssonyan.com>
# Github: https://github.com/trojanpanel/install-script

init_var() {
  ECHO_TYPE="echo -e"

  package_manager=""
  release=""
  get_arch=""
  can_google=0

  # Docker
  DOCKER_MIRROR='"https://registry.docker-cn.com","https://hub-mirror.c.163.com","https://docker.mirrors.ustc.edu.cn"'

  # project directory
  TP_DATA="/tpdata/"

  STATIC_HTML="https://github.com/trojanpanel/install-script/releases/download/v1.0.0/html.tar.gz"

  # Caddy
  CADDY_DATA="/tpdata/caddy/"
  CADDY_Config="/tpdata/caddy/config.json"
  CADDY_SRV="/tpdata/caddy/srv/"
  CADDY_CERT="/tpdata/caddy/cert/"
  CADDY_LOG="/tpdata/caddy/logs/"
  DOMAIN_FILE="/tpdata/caddy/domain.lock"
  CADDY_CERT_DIR="/tpdata/caddy/cert/certificates/acme-v02.api.letsencrypt.org-directory/"
  domain=""
  caddy_port=80
  caddy_remote_port=8863
  your_email=""
  ssl_option=1
  ssl_module_type=1
  ssl_module="acme"
  crt_path=""
  key_path=""

  # trojanGFW
  TROJANGFW_DATA="/tpdata/trojanGFW/"
  TROJANGFW_STANDALONE_CONFIG="/tpdata/trojanGFW/standalone_config.json"
  trojanGFW_port=443
  # trojanGO
  TROJANGO_DATA="/tpdata/trojanGO/"
  TROJANGO_STANDALONE_CONFIG="/tpdata/trojanGO/standalone_config.json"
  trojanGO_port=443
  trojanGO_websocket_enable=false
  trojanGO_websocket_path="trojan-panel-websocket-path"
  trojanGO_shadowsocks_enable=false
  trojanGO_shadowsocks_method="AES-128-GCM"
  trojanGO_shadowsocks_password=""
  trojanGO_mux_enable=true
  # trojan
  trojan_pas=""
  remote_addr="127.0.0.1"

  # hysteria
  HYSTERIA_DATA="/tpdata/hysteria/"
  HYSTERIA_STANDALONE_CONFIG="/tpdata/hysteria/standalone_config.json"
  hysteria_port=443
  hysteria_password=""
  hysteria_protocol="udp"
  hysteria_up_mbps=100
  hysteria_down_mbps=100

  # naiveproxy
  NAIVEPROXY_DATA="/tpdata/naiveproxy/"
  NAIVEPROXY_STANDALONE_CONFIG="/tpdata/naiveproxy/standalone_config.json"
  naiveproxy_port=443
  naiveproxy_username=""
  naiveproxy_pass=""
}

echo_content() {
  case $1 in
  "red")
    ${ECHO_TYPE} "\033[31m$2\033[0m"
    ;;
  "green")
    ${ECHO_TYPE} "\033[32m$2\033[0m"
    ;;
  "yellow")
    ${ECHO_TYPE} "\033[33m$2\033[0m"
    ;;
  "blue")
    ${ECHO_TYPE} "\033[34m$2\033[0m"
    ;;
  "purple")
    ${ECHO_TYPE} "\033[35m$2\033[0m"
    ;;
  "skyBlue")
    ${ECHO_TYPE} "\033[36m$2\033[0m"
    ;;
  "white")
    ${ECHO_TYPE} "\033[37m$2\033[0m"
    ;;
  esac
}

mkdir_tools() {
  # project directory
  mkdir -p ${TP_DATA}

  # Caddy
  mkdir -p ${CADDY_DATA}
  touch ${CADDY_Config}
  mkdir -p ${CADDY_SRV}
  mkdir -p ${CADDY_CERT}
  mkdir -p ${CADDY_LOG}

  # trojanGFW
  mkdir -p ${TROJANGFW_DATA}
  touch ${TROJANGFW_STANDALONE_CONFIG}

  # trojanGO
  mkdir -p ${TROJANGO_DATA}
  touch ${TROJANGO_STANDALONE_CONFIG}

  # hysteria
  mkdir -p ${HYSTERIA_DATA}
  touch ${HYSTERIA_STANDALONE_CONFIG}

  # naiveproxy
  mkdir -p ${NAIVEPROXY_DATA}
  touch ${NAIVEPROXY_STANDALONE_CONFIG}
}

can_connect() {
  ping -c2 -i0.3 -W1 "$1" &>/dev/null
  if [[ "$?" == "0" ]]; then
    return 0
  else
    return 1
  fi
}

check_sys() {
  if [[ $(command -v yum) ]]; then
    package_manager='yum'
  elif [[ $(command -v dnf) ]]; then
    package_manager='dnf'
  elif [[ $(command -v apt) ]]; then
    package_manager='apt'
  elif [[ $(command -v apt-get) ]]; then
    package_manager='apt-get'
  fi

  if [[ -z "${package_manager}" ]]; then
    echo_content red "The system is not currently supported"
    exit 0
  fi

  if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
    release="centos"
  elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
    release="debian"
  elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
    release="ubuntu"
  fi

  if [[ -z "${release}" ]]; then
    echo_content red "only supportCentOS 7+/Ubuntu 18+/Debian 10+system"
    exit 0
  fi

  if [[ $(arch) =~ ("x86_64"|"amd64"|"arm64"|"aarch64"|"arm"|"s390x") ]]; then
    get_arch=$(arch)
  fi

  if [[ -z "${get_arch}" ]]; then
    echo_content red "only supportamd64/arm64/arm/s390xprocessor architecture"
    exit 0
  fi
}

depend_install() {
  if [[ "${package_manager}" != 'yum' && "${package_manager}" != 'dnf' ]]; then
    ${package_manager} update -y
  fi
  ${package_manager} install -y \
    curl \
    wget \
    tar \
    lsof \
    systemd
}

# InstallDocker
install_docker() {
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content green "---> InstallDocker"

    # turn off firewall
    if [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]]; then
      systemctl stop firewalld.service && systemctl disable firewalld.service
    fi

    # Time zone
    timedatectl set-timezone Asia/Shanghai

    can_connect www.google.com
    [[ "$?" == "0" ]] && can_google=1

    if [[ ${can_google} == 0 ]]; then
      sh <(curl -sL https://get.docker.com) --mirror Aliyun
      # set upDockerDomestic source
      mkdir -p /etc/docker &&
        cat >/etc/docker/daemon.json <<EOF
{
  "registry-mirrors":[${DOCKER_MIRROR}],
  "log-driver":"json-file",
  "log-opts":{
      "max-size":"50m",
      "max-file":"3"
  }
}
EOF
    else
      sh <(curl -sL https://get.docker.com)
    fi

    systemctl enable docker &&
      systemctl restart docker

    if [[ $(docker -v 2>/dev/null) ]]; then
      echo_content skyBlue "---> DockerThe installation is complete"
    else
      echo_content red "---> Dockerinstallation failed"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedDocker"
  fi
}

# InstallCaddy TLS
install_caddy_tls() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> InstallCaddy TLS"

    wget --no-check-certificate -O ${CADDY_DATA}html.tar.gz ${STATIC_HTML} &&
      tar -zxvf ${CADDY_DATA}html.tar.gz -C ${CADDY_SRV}

    read -r -p "please enterCaddyport(default:80): " caddy_port
    [[ -z "${caddy_port}" ]] && caddy_port=80
    read -r -p "please enterCaddyForwarding port of(default:8863): " caddy_remote_port
    [[ -z "${caddy_remote_port}" ]] && caddy_remote_port=8863

    echo_content yellow "Tip: Please confirm that the domain name has been resolved to this machine Otherwise the installation may fail"
    while read -r -p "Please enter your domain name(required): " domain; do
      if [[ -z "${domain}" ]]; then
        echo_content red "Domain name cannot be empty"
      else
        break
      fi
    done

    read -r -p "Please enter your email(optional): " your_email

    while read -r -p "Please choose how to set up the certificate?(1/Apply for and renew certificates automatically 2/Manually set the certification path default:1/Apply for and renew certificates automatically): " ssl_option; do
      if [[ -z ${ssl_option} || ${ssl_option} == 1 ]]; then
        while read -r -p "Please choose the way to apply for a certificate(1/acme 2/zerossl default:1/acme): " ssl_module_type; do
          if [[ -z "${ssl_module_type}" || ${ssl_module_type} == 1 ]]; then
            ssl_module="acme"
            CADDY_CERT_DIR="/tpdata/caddy/cert/certificates/acme-v02.api.letsencrypt.org-directory/"
            break
          elif [[ ${ssl_module_type} == 2 ]]; then
            ssl_module="zerossl"
            CADDY_CERT_DIR="/tpdata/caddy/cert/certificates/acme.zerossl.com-v2-dv90/"
            break
          else
            echo_content red "Cannot enter except1and2characters other than"
          fi
        done

        cat >${CADDY_Config} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CADDY_CERT}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${CADDY_SRV}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
        break
      elif [[ ${ssl_option} == 2 ]]; then
        while read -r -p "Please enter the certificate's.crtfile path(required): " crt_path; do
          if [[ -z "${crt_path}" ]]; then
            echo_content red "path cannot be empty"
          else
            if [[ ! -f "${crt_path}" ]]; then
              echo_content red "certificate.crtfile path does not exist"
            else
              cp "${crt_path}" "${CADDY_CERT}${domain}.crt"
              break
            fi
          fi
        done

        while read -r -p "Please enter the certificate's.keyfile path(required): " key_path; do
          if [[ -z "${key_path}" ]]; then
            echo_content red "path cannot be empty"
          else
            if [[ ! -f "${key_path}" ]]; then
              echo_content red "certificate.keyfile path does not exist"
            else
              cp "${key_path}" "${CADDY_CERT}${domain}.key"
              break
            fi
          fi
        done

        cat >${CADDY_Config} <<EOF
{
    "admin":{
        "disabled":true
    },
    "logging":{
        "logs":{
            "default":{
                "writer":{
                    "output":"file",
                    "filename":"${CADDY_LOG}error.log"
                },
                "level":"ERROR"
            }
        }
    },
    "storage":{
        "module":"file_system",
        "root":"${CADDY_CERT}"
    },
    "apps":{
        "http":{
            "http_port": ${caddy_port},
            "servers":{
                "srv0":{
                    "listen":[
                        ":${caddy_port}"
                    ],
                    "routes":[
                        {
                            "match":[
                                {
                                    "host":[
                                        "${domain}"
                                    ]
                                }
                            ],
                            "handle":[
                                {
                                    "handler":"static_response",
                                    "headers":{
                                        "Location":[
                                            "https://{http.request.host}:${caddy_remote_port}{http.request.uri}"
                                        ]
                                    },
                                    "status_code":301
                                }
                            ]
                        }
                    ]
                },
                "srv1":{
                    "listen":[
                        ":${caddy_remote_port}"
                    ],
                    "routes":[
                        {
                            "handle":[
                                {
                                    "handler":"subroute",
                                    "routes":[
                                        {
                                            "match":[
                                                {
                                                    "host":[
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle":[
                                                {
                                                    "handler":"file_server",
                                                    "root":"${CADDY_SRV}",
                                                    "index_names":[
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal":true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies":[
                        {
                            "match":{
                                "sni":[
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https":{
                        "disable":true
                    }
                }
            }
        },
        "tls":{
            "certificates":{
                "automate":[
                    "${domain}"
                ],
                "load_files":[
                    {
                        "certificate":"${CADDY_CERT_DIR}${domain}/${domain}.crt",
                        "key":"${CADDY_CERT_DIR}${domain}/${domain}.key"
                    }
                ]
            },
            "automation":{
                "policies":[
                    {
                        "issuers":[
                            {
                                "module":"${ssl_module}",
                                "email":"${your_email}"
                            }
                        ]
                    }
                ]
            }
        }
    }
}
EOF
        break
      else
        echo_content red "Cannot enter except1and2characters other than"
      fi
    done

    if [[ -n $(lsof -i:${caddy_port},443 -t) ]]; then
      kill -9 "$(lsof -i:${caddy_port},443 -t)"
    fi

    docker pull caddy:2.6.2 &&
      docker run -d --name trojan-panel-caddy --restart always \
        --network=host \
        -v "${CADDY_Config}":"${CADDY_Config}" \
        -v ${CADDY_CERT}:"${CADDY_CERT_DIR}${domain}/" \
        -v ${CADDY_SRV}:${CADDY_SRV} \
        -v ${CADDY_LOG}:${CADDY_LOG} \
        caddy:2.6.2 caddy run --config ${CADDY_Config}

    if [[ -n $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
      cat >${DOMAIN_FILE} <<EOF
${domain}
EOF
      echo_content skyBlue "---> CaddyThe installation is complete"
    else
      echo_content red "---> CaddyFailed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    domain=$(cat "${DOMAIN_FILE}")
    echo_content skyBlue "---> you have installedCaddy"
  fi
}

# TrojanGFW+Caddy+Web+TLS+Websocket
install_trojan_gfw_standalone() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-trojanGFW-standalone$") ]]; then
    echo_content green "---> InstallTrojanGFW+Caddy+Web+TLS+Websocket"

    read -r -p "please enterTrojanGFWport(default:443): " trojanGFW_port
    [[ -n ${trojanGFW_port} ]] && trojanGFW_port=443
    while read -r -p "please enterTrojanGFWpassword for(required): " trojan_pas; do
      if [[ -z "${trojan_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    cat >${TROJANGFW_STANDALONE_CONFIG} <<EOF
    {
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": ${trojanGFW_port},
    "remote_addr": "${remote_addr}",
    "remote_port": 80,
    "password": [
        "${trojan_pas}"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "${CADDY_CERT}${domain}.crt",
        "key": "${CADDY_CERT}${domain}.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "alpn_port_override": {
            "h2": 81
        },
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "",
        "username": "",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF

    docker pull trojangfw/trojan &&
      docker run -d --name trojan-panel-trojanGFW-standalone --restart always \
        --network=host \
        -v ${TROJANGFW_STANDALONE_CONFIG}:"/config/config.json" \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        trojangfw/trojan

    if [[ -n $(docker ps -q -f "name=^trojan-panel-trojanGFW-standalone$" -f "status=running") ]]; then
      echo_content skyBlue "---> TrojanGFW+Caddy+Web+TLS The installation is complete"
      echo_content red "\n=============================================================="
      echo_content skyBlue "TrojanGFW+Caddy+Web+TLS Successful installation"
      echo_content yellow "domain name: ${domain}"
      echo_content yellow "TrojanGFWport: ${trojanGFW_port}"
      echo_content yellow "TrojanGFWpassword for: ${trojan_pas}"
      echo_content red "\n=============================================================="
    else
      echo_content red "---> TrojanGFW+Caddy+Web+TLS Failed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedTrojanGFW+Caddy+Web+TLS"
  fi
}

# TrojanGO+Caddy+Web+TLS+Websocket
install_trojanGO_standalone() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-trojanGO-standalone$") ]]; then
    echo_content green "---> InstallTrojanGO+Caddy+Web+TLS+Websocket"

    read -r -p "please enterTrojanGOport(default:443): " trojanGO_port
    [[ -z "${trojanGO_port}" ]] && trojanGO_port=443
    while read -r -p "please enterTrojanGOpassword for(required): " trojan_pas; do
      if [[ -z "${trojan_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    while read -r -p "Whether to enable multiplexing?(false/closure true/turn on default:true/turn on): " trojanGO_mux_enable; do
      if [[ -z "${trojanGO_mux_enable}" || ${trojanGO_mux_enable} == true ]]; then
        trojanGO_mux_enable=true
        break
      else
        if [[ ${trojanGO_mux_enable} != false ]]; then
          echo_content red "Cannot enter exceptfalseandtruecharacters other than"
        else
          break
        fi
      fi
    done

    while read -r -p "whether to openWebsocket?(false/closure true/turn on default:false/closure): " trojanGO_websocket_enable; do
      if [[ -z "${trojanGO_websocket_enable}" || ${trojanGO_websocket_enable} == false ]]; then
        trojanGO_websocket_enable=false
        break
      else
        if [[ ${trojanGO_websocket_enable} != true ]]; then
          echo_content red "Cannot enter exceptfalseandtruecharacters other than"
        else
          read -r -p "please enterWebsocketpath(default:trojan-panel-websocket-path): " trojanGO_websocket_path
          [[ -z "${trojanGO_websocket_path}" ]] && trojanGO_websocket_path="trojan-panel-websocket-path"
          break
        fi
      fi
    done

    while read -r -p "Whether to enableShadowsocks AEADencryption?(false/closure true/turn on default:false/closure): " trojanGO_shadowsocks_enable; do
      if [[ -z "${trojanGO_shadowsocks_enable}" || ${trojanGO_shadowsocks_enable} == false ]]; then
        trojanGO_shadowsocks_enable=false
        break
      else
        if [[ ${trojanGO_shadowsocks_enable} != true ]]; then
          echo_content yellow "Cannot enter exceptfalseandtruecharacters other than"
        else
          echo_content skyBlue "Shadowsocks AEADThe encryption method is as follows:"
          echo_content yellow "1. AES-128-GCM(default)"
          echo_content yellow "2. CHACHA20-IETF-POLY1305"
          echo_content yellow "3. AES-256-GCM"
          read -r -p "please enterShadowsocks AEADEncryption(default:1): " select_method_type
          [[ -z "${select_method_type}" ]] && select_method_type=1
          case ${select_method_type} in
          1)
            trojanGO_shadowsocks_method="AES-128-GCM"
            ;;
          2)
            trojanGO_shadowsocks_method="CHACHA20-IETF-POLY1305"
            ;;
          3)
            trojanGO_shadowsocks_method="AES-256-GCM"
            ;;
          *)
            trojanGO_shadowsocks_method="AES-128-GCM"
            ;;
          esac

          while read -r -p "please enterShadowsocks AEADencrypted password(required): " trojanGO_shadowsocks_password; do
            if [[ -z "${trojanGO_shadowsocks_password}" ]]; then
              echo_content red "password can not be blank"
            else
              break
            fi
          done
          break
        fi
      fi
    done

    cat >${TROJANGO_STANDALONE_CONFIG} <<EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": ${trojanGO_port},
  "remote_addr": "${remote_addr}",
  "remote_port": 80,
  "log_level": 1,
  "log_file": "",
  "password": [
      "${trojan_pas}"
  ],
  "disable_http_check": false,
  "udp_timeout": 60,
  "ssl": {
    "verify": true,
    "verify_hostname": true,
    "cert": "${CADDY_CERT}${domain}.crt",
    "key": "${CADDY_CERT}${domain}.key",
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "",
    "fallback_port": 80,
    "fingerprint": ""
  },
  "tcp": {
    "no_delay": true,
    "keep_alive": true,
    "prefer_ipv4": false
  },
    "mux": {
    "enabled": ${trojanGO_mux_enable},
    "concurrency": 8,
    "idle_timeout": 60
  },
  "websocket": {
    "enabled": ${trojanGO_websocket_enable},
    "path": "/${trojanGO_websocket_path}",
    "host": "${domain}"
  },
  "shadowsocks": {
    "enabled": ${trojanGO_shadowsocks_enable},
    "method": "${trojanGO_shadowsocks_method}",
    "password": "${trojanGO_shadowsocks_password}"
  },
  "mysql": {
    "enabled": false,
    "server_addr": "localhost",
    "server_port": 3306,
    "database": "",
    "username": "",
    "password": "",
    "check_rate": 60
  }
}
EOF

    docker pull p4gefau1t/trojan-go &&
      docker run -d --name trojan-panel-trojanGO-standalone --restart=always \
        --network=host \
        -v ${TROJANGO_STANDALONE_CONFIG}:"/etc/trojan-go/config.json" \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        p4gefau1t/trojan-go

    if [[ -n $(docker ps -q -f "name=^trojan-panel-trojanGO-standalone$" -f "status=running") ]]; then
      echo_content skyBlue "---> TrojanGO+Caddy+Web+TLS+Websocket The installation is complete"
      echo_content red "\n=============================================================="
      echo_content skyBlue "TrojanGO+Caddy+Web+TLS+Websocket Successful installation"
      echo_content yellow "domain name: ${domain}"
      echo_content yellow "TrojanGOport: ${trojanGO_port}"
      echo_content yellow "TrojanGOpassword for: ${trojan_pas}"
      echo_content yellow "TrojanGOPrivate key and certificate directory: ${CADDY_CERT}"
      if [[ ${trojanGO_websocket_enable} == true ]]; then
        echo_content yellow "Websocketpath: ${trojanGO_websocket_path}"
      fi
      if [[ ${trojanGO_shadowsocks_enable} == true ]]; then
        echo_content yellow "Shadowsocks AEADEncryption: ${trojanGO_shadowsocks_method}"
        echo_content yellow "Shadowsocks AEADencrypted password: ${trojanGO_shadowsocks_password}"
      fi
      echo_content red "\n=============================================================="
    else
      echo_content red "---> TrojanGO+Caddy+Web+TLS+Websocket Failed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedTrojanGO+Caddy+Web+TLS+Websocket"
  fi
}

# InstallHysteria
install_hysteria_standalone() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-hysteria-standalone$") ]]; then
    echo_content green "---> InstallHysteria"

    echo_content skyBlue "HysteriaThe schema is as follows:"
    echo_content yellow "1. udp(default)"
    echo_content yellow "2. faketcp"
    read -r -p "please enterHysteriamode(default:1): " selectProtocolType
    [[ -z "${selectProtocolType}" ]] && selectProtocolType=1
    case ${selectProtocolType} in
    1)
      hysteria_protocol="udp"
      ;;
    2)
      hysteria_protocol="faketcp"
      ;;
    *)
      hysteria_protocol="udp"
      ;;
    esac
    read -r -p "please enterHysteriaport(default:443): " hysteria_port
    [[ -z ${hysteria_port} ]] && hysteria_port=443
    read -r -p "Please enter the maximum upload speed of a single client/Mbps(default:100): " hysteria_up_mbps
    [[ -z "${hysteria_up_mbps}" ]] && hysteria_up_mbps=100
    read -r -p "Please enter the maximum download speed of a single client/Mbps(default:100): " hysteria_down_mbps
    [[ -z "${hysteria_down_mbps}" ]] && hysteria_down_mbps=100
    while read -r -p "please enterHysteriapassword for(required): " hysteria_password; do
      if [[ -z ${hysteria_password} ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    cat >${HYSTERIA_STANDALONE_CONFIG} <<EOF
{
  "listen": ":${hysteria_port}",
  "protocol": "${hysteria_protocol}",
  "cert": "${CADDY_CERT}${domain}.crt",
  "key": "${CADDY_CERT}${domain}.key",
  "up_mbps": ${hysteria_up_mbps},
  "down_mbps": ${hysteria_down_mbps},
  "auth_str": "${hysteria_password}"
}
EOF

    docker pull tobyxdd/hysteria &&
      docker run -d --name trojan-panel-hysteria-standalone --restart=always \
        --network=host \
        -v ${HYSTERIA_STANDALONE_CONFIG}:/etc/hysteria.json \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        tobyxdd/hysteria -c /etc/hysteria.json server

    if [[ -n $(docker ps -q -f "name=^trojan-panel-hysteria-standalone$" -f "status=running") ]]; then
      echo_content skyBlue "---> Hysteria The installation is complete"
      echo_content red "\n=============================================================="
      echo_content skyBlue "Hysteria Successful installation"
      echo_content yellow "domain name: ${domain}"
      echo_content yellow "Hysteriaport: ${hysteria_port}"
      echo_content yellow "Hysteriapassword for: ${hysteria_password}"
      echo_content yellow "HysteriaPrivate key and certificate directory: ${CADDY_CERT}"
      echo_content red "\n=============================================================="
    else
      echo_content red "---> Hysteria Failed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedHysteria"
  fi
}

# InstallNaiveProxy(Caddy+ForwardProxy)
install_navieproxy_standalone() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-navieproxy-standalone$") ]]; then
    echo_content green "---> InstallNaiveProxy(Caddy+ForwardProxy)"

    read -r -p "please enterNaiveProxyport(default:443): " naiveproxy_port
    [[ -z "${naiveproxy_port}" ]] && naiveproxy_port=443
    while read -r -p "please enterNaiveProxyusername for(required): " naiveproxy_username; do
      if [[ -z "${naiveproxy_username}" ]]; then
        echo_content red "Username can not be empty"
      else
        break
      fi
    done
    while read -r -p "please enterNaiveProxypassword for(required): " naiveproxy_pass; do
      if [[ -z "${naiveproxy_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done
    domain=$(cat "${DOMAIN_FILE}")
    cat >${NAIVEPROXY_STANDALONE_CONFIG} <<EOF
{
    "admin": {
        "disabled": true
    },
    "logging": {
        "sink": {
            "writer": {
                "output": "discard"
            }
        },
        "logs": {
            "default": {
                "writer": {
                    "output": "discard"
                }
            }
        }
    },
    "apps": {
        "http": {
            "servers": {
                "srv0": {
                    "listen": [
                        ":${naiveproxy_port}"
                    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "subroute",
                                    "routes": [
                                        {
                                            "handle": [
                                                {
                                                    "auth_pass_deprecated": "${naiveproxy_pass}",
                                                    "auth_user_deprecated": "${naiveproxy_username}",
                                                    "handler": "forward_proxy",
                                                    "hide_ip": true,
                                                    "hide_via": true,
                                                    "probe_resistance": {}
                                                }
                                            ]
                                        },
                                        {
                                            "match": [
                                                {
                                                    "host": [
                                                        "${domain}"
                                                    ]
                                                }
                                            ],
                                            "handle": [
                                                {
                                                    "handler": "file_server",
                                                    "root": "/caddy-forwardproxy/dist/",
                                                    "index_names": [
                                                        "index.html",
                                                        "index.htm"
                                                    ]
                                                }
                                            ],
                                            "terminal": true
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "tls_connection_policies": [
                        {
                            "match": {
                                "sni": [
                                    "${domain}"
                                ]
                            }
                        }
                    ],
                    "automatic_https": {
                        "disable": true
                    }
                }
            }
        },
        "tls": {
            "certificates": {
                "load_files": [
                    {
                        "certificate": "${CADDY_CERT}${domain}.crt",
                        "key": "${CADDY_CERT}${domain}.crt"
                    }
                ]
            }
        }
    }
}
EOF
    docker pull jonssonyan/caddy-forwardproxy &&
      docker run -d --name trojan-panel-navieproxy-standalone --restart=always \
        --network=host \
        -v ${NAIVEPROXY_STANDALONE_CONFIG}:"/caddy-forwardproxy/config/config.json" \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        jonssonyan/caddy-forwardproxy

    if [[ -n $(docker ps -q -f "name=^trojan-panel-navieproxy-standalone$" -f "status=running") ]]; then
      echo_content skyBlue "---> NaiveProxy(Caddy+ForwardProxy) The installation is complete"
      echo_content red "\n=============================================================="
      echo_content skyBlue "NaiveProxy(Caddy+ForwardProxy) Successful installation"
      echo_content yellow "domain name: ${domain}"
      echo_content yellow "NaiveProxyport: ${naiveproxy_port}"
      echo_content yellow "NaiveProxyusername for: ${naiveproxy_username}"
      echo_content yellow "NaiveProxypassword for: ${naiveproxy_pass}"
      echo_content yellow "NaiveProxyPrivate key and certificate directory: ${CADDY_CERT}"
      echo_content red "\n=============================================================="
    else
      echo_content red "---> NaiveProxy(Caddy+ForwardProxy) Failed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedNaiveProxy(Caddy+ForwardProxy)"
  fi
}

# uninstallCaddy TLS
uninstall_caddy_tls() {
  # judgmentCaddy TLSWhether to install
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
    echo_content green "---> uninstallCaddy TLS"

    docker rm -f trojan-panel-caddy &&
      rm -rf ${CADDY_DATA}

    echo_content skyBlue "---> Caddy TLSuninstall complete"
  else
    echo_content red "---> please install firstCaddy TLS"
  fi
}

# TrojanGFW+Caddy+Web+TLS
uninstall_trojan_gfw_standalone() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-trojanGFW-standalone$") ]]; then
    echo_content green "---> uninstallTrojanGFW+Caddy+Web+TLS"

    docker rm -f trojan-panel-trojanGFW-standalone &&
      docker rmi -f trojangfw/trojan &&
      rm -f ${TROJANGFW_STANDALONE_CONFIG}

    echo_content skyBlue "---> TrojanGFW+Caddy+Web+TLS uninstall complete"
  else
    echo_content red "---> please install firstTrojanGFW+Caddy+Web+TLS"
  fi
}

# uninstallTrojanGO single vision
uninstall_trojanGO_standalone() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-trojanGO-standalone$") ]]; then
    echo_content green "---> uninstallTrojanGO+Caddy+Web+TLS+Websocket"

    docker rm -f trojan-panel-trojanGO-standalone &&
      docker rmi -f p4gefau1t/trojan-go &&
      rm -f ${TROJANGO_STANDALONE_CONFIG}

    echo_content skyBlue "---> TrojanGO+Caddy+Web+TLS+Websocket uninstall complete"
  else
    echo_content red "---> please install firstTrojanGO+Caddy+Web+TLS+Websocket"
  fi
}

# uninstallHysteria
uninstall_hysteria_standalone() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-hysteria-standalone$") ]]; then
    echo_content green "---> uninstallHysteria"

    docker rm -f trojan-panel-hysteria-standalone &&
      docker rmi -f tobyxdd/hysteria &&
      rm -f ${HYSTERIA_STANDALONE_CONFIG}

    echo_content skyBlue "---> Hysteria uninstall complete"
  else
    echo_content red "---> please install firstHysteria"
  fi
}

# uninstallNaiveProxy(Caddy+ForwardProxy)
uninstall_navieproxy_standalone() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-navieproxy-standalone$") ]]; then
    echo_content green "---> uninstallNaiveProxy(Caddy+ForwardProxy)"

    docker rm -f trojan-panel-navieproxy-standalone &&
      docker rmi -f jonssonyan/caddy-forwardproxy &&
      rm -f ${NAIVEPROXY_STANDALONE_CONFIG}

    echo_content skyBlue "---> NaiveProxy(Caddy+ForwardProxy) uninstall complete"
  else
    echo_content red "---> please install firstNaiveProxy(Caddy+ForwardProxy)"
  fi
}

# uninstall allTrojan Panelrelated container
uninstall_all() {
  echo_content green "---> uninstall allTrojan Panelrelated container"

  docker rm -f $(docker ps -a -q -f "name=^trojan-panel") &&
    rm -rf ${TP_DATA}

  echo_content skyBlue "---> uninstall allTrojan PanelThe associated container completes"
}

# Fault detection
failure_testing() {
  echo_content green "---> Troubleshooting starts"
  if [[ ! $(docker -v 2>/dev/null) ]]; then
    echo_content red "---> DockerAbnormal operation"
  else
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-caddy$") ]]; then
      if [[ -z $(docker ps -q -f "name=^trojan-panel-caddy$" -f "status=running") ]]; then
        echo_content red "---> Caddy TLSAbnormal operation The error log is as follows:"
        docker logs trojan-panel-caddy
      fi
      domain=$(cat "${DOMAIN_FILE}")
      if [[ -z $(cat "${DOMAIN_FILE}") || ! -d "${CADDY_CERT}" || ! -f "${CADDY_CERT}${domain}.crt" ]]; then
        echo_content red "---> The certificate application is abnormal, please try 1.Rebuild with another subdomain 2.Restarting the server will reapply for the certificate 3.Rebuild select custom certificate option The log is as follows:"
        if [[ -f ${CADDY_LOG}error.log ]]; then
          tail -n 20 ${CADDY_LOG}error.log
        else
          docker logs trojan-panel-caddy
        fi
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-trojanGFW-standalone$") && -z $(docker ps -q -f "name=^trojan-panel-trojanGFW-standalone$" -f "status=running") ]]; then
      echo_content red "---> TrojanGFWAbnormal operation"
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-trojanGO-standalone$") && -z $(docker ps -q -f "name=^trojan-panel-trojanGO-standalone$" -f "status=running") ]]; then
      echo_content red "---> TrojanGOAbnormal operation"
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-hysteria-standalone$") && -z $(docker ps -q -f "name=^trojan-panel-hysteria-standalone$" -f "status=running") ]]; then
      echo_content red "---> HysteriaAbnormal operation"
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-navieproxy-standalone$") && -z $(docker ps -q -f "name=^trojan-panel-navieproxy-standalone$" -f "status=running") ]]; then
      echo_content red "---> NaiveProxy(Caddy+ForwardProxy)Abnormal operation"
    fi
  fi
  echo_content green "---> Troubleshooting ended"
}

main() {
  cd "$HOME" || exit 0
  init_var
  mkdir_tools
  check_sys
  depend_install
  clear
  echo_content red "\n=============================================================="
  echo_content skyBlue "System Required: CentOS 7+/Ubuntu 18+/Debian 10+"
  echo_content skyBlue "Version: v2.0.4"
  echo_content skyBlue "Description: One click Install Trojan Panel standalone server"
  echo_content skyBlue "Author: jonssonyan <https://jonssonyan.com>"
  echo_content skyBlue "Github: https://github.com/trojanpanel"
  echo_content skyBlue "Docs: https://trojanpanel.github.io"
  echo_content red "\n=============================================================="
  echo_content yellow "1. InstallTrojanGFW+Caddy+Web+TLS"
  echo_content yellow "2. InstallTrojanGO+Caddy+Web+TLS+Websocket"
  echo_content yellow "3. InstallHysteria"
  echo_content yellow "4. InstallNaiveProxy(Caddy+ForwardProxy)"
  echo_content yellow "5. InstallCaddy TLS"
  echo_content green "\n=============================================================="
  echo_content yellow "6. uninstallTrojanGFW+Caddy+Web+TLS"
  echo_content yellow "7. uninstallTrojanGO+Caddy+Web+TLS+Websocket"
  echo_content yellow "8. uninstallHysteria"
  echo_content yellow "9. uninstallNaiveProxy(Caddy+ForwardProxy)"
  echo_content yellow "10. uninstallCaddy TLS"
  echo_content yellow "11. uninstall allTrojan Panelrelated applications"
  echo_content green "\n=============================================================="
  echo_content yellow "12. Fault detection"
  read -r -p "please choose:" selectInstall_type
  case ${selectInstall_type} in
  1)
    install_docker
    install_caddy_tls
    install_trojan_gfw_standalone
    ;;
  2)
    install_docker
    install_caddy_tls
    install_trojanGO_standalone
    ;;
  3)
    install_docker
    install_caddy_tls
    install_hysteria_standalone
    ;;
  4)
    install_docker
    install_caddy_tls
    install_navieproxy_standalone
    ;;
  5)
    install_docker
    install_caddy_tls
    ;;
  6)
    uninstall_trojan_gfw_standalone
    ;;
  7)
    uninstall_trojanGO_standalone
    ;;
  8)
    uninstall_hysteria_standalone
    ;;
  9)
    uninstall_navieproxy_standalone
    ;;
  10)
    uninstall_caddy_tls
    ;;
  11)
    uninstall_all
    ;;
  12)
    failure_testing
    ;;
  *)
    echo_content red "no such option"
    ;;
  esac
}

main