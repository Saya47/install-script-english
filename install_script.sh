#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# System Required: CentOS 7+/Ubuntu 18+/Debian 10+
# Version: v2.0.4
# Description: One click Install Trojan Panel server
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

  # MariaDB
  MARIA_DATA="/tpdata/mariadb/"
  mariadb_ip="127.0.0.1"
  mariadb_port=9507
  mariadb_user="root"
  mariadb_pas=""

  #Redis
  REDIS_DATA="/tpdata/redis/"
  redis_host="127.0.0.1"
  redis_port=6378
  redis_pass=""

  # Trojan Panel
  TROJAN_PANEL_DATA="/tpdata/trojan-panel/"
  TROJAN_PANEL_WEBFILE="/tpdata/trojan-panel/webfile/"
  TROJAN_PANEL_LOGS="/tpdata/trojan-panel/logs/"

  # Trojan Panel UI
  TROJAN_PANEL_UI_DATA="/tpdata/trojan-panel-ui/"
  # Nginx
  NGINX_DATA="/tpdata/nginx/"
  NGINX_CONFIG="/tpdata/nginx/default.conf"
  trojan_panel_ui_port=8888
  https_enable=1

  # Trojan Panel Core
  TROJAN_PANEL_CORE_DATA="/tpdata/trojan-panel-core/"
  TROJAN_PANEL_CORE_LOGS="/tpdata/trojan-panel-core/logs/"
  TROJAN_PANEL_CORE_SQLITE="/tpdata/trojan-panel-core/config/sqlite/"
  database="trojan_panel_db"
  account_table="account"
  grpc_port=8100

  # Update
  trojan_panel_current_version=""
  trojan_panel_latest_version="v2.0.4"
  trojan_panel_core_current_version=""
  trojan_panel_core_latest_version="v2.0.3"

  # SQL
  sql_200="alter table \`system\` add template_config varchar(512) default '' not null comment 'template settings' after email_config;update \`system\` set template_config = \"{\\\"systemName\\\":\\\"Trojan Panel\\\"}\" where name = \"trojan-panel\";insert into \`casbin_rule\` values ('p','sysadmin','/api/nodeServer/nodeServerState','GET','','','');insert into \`casbin_rule\` values ('p','user','/api/node/selectNodeInfo','GET','','','');insert into \`casbin_rule\` values ('p','sysadmin','/api/node/selectNodeInfo','GET','','','');"
  sql_203="alter table node add node_server_grpc_port int(10) unsigned default 8100 not null comment 'gRPCport' after node_server_ip;alter table node_server add grpc_port int(10) unsigned default 8100 not null comment 'gRPCport' after name;alter table node_xray add xray_flow varchar(32) default 'xtls-rprx-vision' not null comment 'XrayFlow Control' after protocol;alter table node_xray add xray_ss_method varchar(32) default 'aes-256-gcm' not null comment 'Xray ShadowsocksEncryption' after xray_flow;"
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

  # MariaDB
  mkdir -p ${MARIA_DATA}

  # Redis
  mkdir -p ${REDIS_DATA}

  # Trojan Panel
  mkdir -p ${TROJAN_PANEL_DATA}
  mkdir -p ${TROJAN_PANEL_LOGS}

  # Trojan Panel UI
  mkdir -p ${TROJAN_PANEL_UI_DATA}
  # # Nginx
  mkdir -p ${NGINX_DATA}
  touch ${NGINX_CONFIG}

  # Trojan Panel Core
  mkdir -p ${TROJAN_PANEL_CORE_DATA}
  mkdir -p ${TROJAN_PANEL_CORE_LOGS}
  mkdir -p ${TROJAN_PANEL_CORE_SQLITE}
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

# InstallMariaDB
install_mariadb() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> InstallMariaDB"

    read -r -p "Please enter the port of the database(default:9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username(default:root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password(required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    if [[ "${mariadb_user}" == "root" ]]; then
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Shanghai \
          mariadb:10.7.3 \
          --port ${mariadb_port}
    else
      docker pull mariadb:10.7.3 &&
        docker run -d --name trojan-panel-mariadb --restart always \
          --network=host \
          -e MYSQL_DATABASE="trojan_panel_db" \
          -e MYSQL_ROOT_PASSWORD="${mariadb_pas}" \
          -e MYSQL_USER="${mariadb_user}" \
          -e MYSQL_PASSWORD="${mariadb_pas}" \
          -e TZ=Asia/Shanghai \
          mariadb:10.7.3 \
          --port ${mariadb_port}
    fi

    if [[ -n $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content skyBlue "---> MariaDBThe installation is complete"
      echo_content yellow "---> MariaDB rootdatabase password for(please keep it safe): ${mariadb_pas}"
      if [[ "${mariadb_user}" != "root" ]]; then
        echo_content yellow "---> MariaDB ${mariadb_user}database password for(please keep it safe): ${mariadb_pas}"
      fi
    else
      echo_content red "---> MariaDBFailed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedMariaDB"
  fi
}

# InstallRedis
install_redis() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> InstallRedis"

    read -r -p "please enterRedisport(default:6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "please enterRedispassword for(required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    docker pull redis:6.2.7 &&
      docker run -d --name trojan-panel-redis --restart always \
        --network=host \
        redis:6.2.7 \
        redis-server --requirepass "${redis_pass}" --port ${redis_port}

    if [[ -n $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content skyBlue "---> RedisThe installation is complete"
      echo_content yellow "---> Redisdatabase password for(please keep it safe): ${redis_pass}"
    else
      echo_content red "---> RedisFailed to install or run abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedRedis"
  fi
}

# InstallTrojanPanel
install_trojan_panel() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> InstallTrojan Panel"

    read -r -p "Please enter the database'sIPaddress(default:native database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of the database(default:9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username(default:root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password(required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -e "create database if not exists trojan_panel_db;" &>/dev/null

    read -r -p "please enterRedisofIPaddress(default:this machineRedis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "please enterRedisport(default:6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "please enterRedispassword for(required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker pull jonssonyan/trojan-panel &&
      docker run -d --name trojan-panel --restart always \
        --network=host \
        -v ${CADDY_SRV}:${TROJAN_PANEL_WEBFILE} \
        -v ${TROJAN_PANEL_LOGS}:${TROJAN_PANEL_LOGS} \
        -v /etc/localtime:/etc/localtime \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        jonssonyan/trojan-panel

    if [[ -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan PanelBackend installation complete"
    else
      echo_content red "---> Trojan PanelThe backend installation fails or runs abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedTrojan Panelrear end"
  fi

  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-ui$") ]]; then
    read -r -p "please enterTrojan Panelfront port(default:8888): " trojan_panel_ui_port
    [[ -z "${trojan_panel_ui_port}" ]] && trojan_panel_ui_port="8888"

    while read -r -p "please chooseTrojan PanelWhether the front end is turned onhttps?(0/closure 1/turn on default:1/turn on): " https_enable; do
      if [[ -z ${https_enable} || ${https_enable} == 1 ]]; then
        # configurationNginx
        cat >${NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port} ssl;
    server_name  ${domain};

    #mandatoryssl
    ssl on;
    ssl_certificate      ${CADDY_CERT}${domain}.crt;
    ssl_certificate_key  ${CADDY_CERT}${domain}.key;
    #Cache validity period
    ssl_session_timeout  5m;
    #Secure Link Optional Encryption Protocol
    ssl_protocols  TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    #Encryption Algorithm
    ssl_ciphers  ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    #Use server-side preferred algorithm
    ssl_prefer_server_ciphers  on;

    #access_log  /var/log/nginx/host.access.log  main;

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_pass http://127.0.0.1:8081;
    }

    #error_page  404              /404.html;
    #497 http->https
    error_page  497              https://\$host:${trojan_panel_ui_port}\$uri?\$args;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
        break
      else
        if [[ ${https_enable} != 0 ]]; then
          echo_content red "Cannot enter except0and1characters other than"
        else
          cat >${NGINX_CONFIG} <<-EOF
server {
    listen       ${trojan_panel_ui_port};
    server_name  localhost;

    location / {
        root   ${TROJAN_PANEL_UI_DATA};
        index  index.html index.htm;
    }

    location /api {
        proxy_pass http://127.0.0.1:8081;
    }

    error_page  497              http://\$host:${trojan_panel_ui_port}\$uri?\$args;

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF
          break
        fi
      fi
    done

    docker pull jonssonyan/trojan-panel-ui &&
      docker run -d --name trojan-panel-ui --restart always \
        --network=host \
        -v "${NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        jonssonyan/trojan-panel-ui

    if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan PanelFront end installation complete"
    else
      echo_content red "---> Trojan PanelThe front-end installation fails or runs abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedTrojan Panelfront end"
  fi

  https_flag=$([[ -z ${https_enable} || ${https_enable} == 1 ]] && echo "https" || echo "http")

  echo_content red "\n=============================================================="
  echo_content skyBlue "Trojan Panel Successful installation"
  echo_content yellow "MariaDB ${mariadb_user}password for(please keep it safe): ${mariadb_pas}"
  echo_content yellow "Redispassword for(please keep it safe): ${redis_pass}"
  echo_content yellow "Admin panel address: ${https_flag}://${domain}:${trojan_panel_ui_port}"
  echo_content yellow "System administrator default username: sysadmin default password: 123456 Please log in to the management panel to change the password in time"
  echo_content yellow "Trojan PanelPrivate key and certificate directory: ${CADDY_CERT}"
  echo_content red "\n=============================================================="
}

# InstallTrojan Panel Core
install_trojan_panel_core() {
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> InstallTrojan Panel Core"

    read -r -p "Please enter the database'sIPaddress(default:native database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of the database(default:9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username(default:root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password(required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done
    read -r -p "Please enter a database name(default:trojan_panel_db): " database
    [[ -z "${database}" ]] && database="trojan_panel_db"
    read -r -p "Please enter the user table name of the database(default:account): " account_table
    [[ -z "${account_table}" ]] && account_table="account"

    read -r -p "please enterRedisofIPaddress(default:this machineRedis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "please enterRedisport(default:6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "please enterRedispassword for(required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done
    read -r -p "please enterAPIport(default:8100): " grpc_port
    [[ -z "${grpc_port}" ]] && grpc_port=8100

    domain=$(cat "${DOMAIN_FILE}")

    docker pull jonssonyan/trojan-panel-core &&
      docker run -d --name trojan-panel-core --restart always \
        --network=host \
        -v ${TROJAN_PANEL_CORE_DATA}bin/xray/config:${TROJAN_PANEL_CORE_DATA}bin/xray/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/trojango/config:${TROJAN_PANEL_CORE_DATA}bin/trojango/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria/config:${TROJAN_PANEL_CORE_DATA}bin/hysteria/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config:${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config \
        -v ${TROJAN_PANEL_CORE_LOGS}:${TROJAN_PANEL_CORE_LOGS} \
        -v ${TROJAN_PANEL_CORE_SQLITE}:${TROJAN_PANEL_CORE_SQLITE} \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        -v ${CADDY_SRV}:${CADDY_SRV} \
        -v /etc/localtime:/etc/localtime \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "database=${database}" \
        -e "account-table=${account_table}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "crt_path=${CADDY_CERT}${domain}.crt" \
        -e "key_path=${CADDY_CERT}${domain}.key" \
        -e "grpc_port=${grpc_port}" \
        jonssonyan/trojan-panel-core
    if [[ -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel CoreThe installation is complete"
    else
      echo_content red "---> Trojan Panel CoreThe backend installation fails or runs abnormally,Please try to repair or uninstall and reinstall"
      exit 0
    fi
  else
    echo_content skyBlue "---> you have installedTrojan Panel Core"
  fi
}

# renewTrojan Paneldata structure
update__trojan_panel_database() {
  echo_content skyBlue "---> renewTrojan Paneldata structure"

  if [[ "${trojan_panel_current_version}" == "v1.3.1" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_200}" &>/dev/null &&
      trojan_panel_current_version="v2.0.0"
  fi
  version_200_203=("v2.0.0" "v2.0.1" "v2.0.2")
  if [[ "${version_200_203[*]}" =~ "${trojan_panel_current_version}" ]]; then
    docker exec trojan-panel-mariadb mysql -h"${mariadb_ip}" -P"${mariadb_port}" -u"${mariadb_user}" -p"${mariadb_pas}" -Dtrojan_panel_db -e "${sql_203}" &>/dev/null &&
      trojan_panel_current_version="v2.0.3"
  fi

  echo_content skyBlue "---> Trojan PanelData structure update complete"
}

# renewTrojan Panel Coredata structure
update__trojan_panel_core_database() {
  echo_content skyBlue "---> renewTrojan Panel Coredata structure"

  echo_content skyBlue "---> Trojan Panel CoreData structure update complete"
}

# renewTrojan Panel
update_trojan_panel() {
  # judgmentTrojan PanelWhether to install
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content red "---> please install firstTrojan Panel"
    exit 0
  fi

  trojan_panel_current_version=$(docker exec trojan-panel ./trojan-panel -version)
  if [[ -z "${trojan_panel_current_version}" || ! "${trojan_panel_current_version}" =~ ^v.* ]]; then
    echo_content red "---> The current version does not support automatic updates"
    exit 0
  fi

  echo_content yellow "hint:Trojan Panelrear end(trojan-panel)The current version is ${trojan_panel_current_version} The latest version is ${trojan_panel_latest_version}"

  if [[ "${trojan_panel_current_version}" != "${trojan_panel_latest_version}" ]]; then
    echo_content green "---> renewTrojan Panel"

    read -r -p "Please enter the database'sIPaddress(default:native database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of the database(default:9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username(default:root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password(required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    read -r -p "please enterRedisofIPaddress(default:this machineRedis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "please enterRedisport(default:6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "please enterRedispassword for(required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done

    update__trojan_panel_database

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker rm -f trojan-panel &&
      docker rmi -f jonssonyan/trojan-panel

    docker pull jonssonyan/trojan-panel &&
      docker run -d --name trojan-panel --restart always \
        --network=host \
        -v ${CADDY_SRV}:${TROJAN_PANEL_WEBFILE} \
        -v ${TROJAN_PANEL_LOGS}:${TROJAN_PANEL_LOGS} \
        -v /etc/localtime:/etc/localtime \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        jonssonyan/trojan-panel

    if [[ -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan PanelBackend update complete"
    else
      echo_content red "---> Trojan PanelThe backend update fails or runs abnormally,Please try to repair or uninstall and reinstall"
    fi

    docker rm -f trojan-panel-ui &&
      docker rmi -f jonssonyan/trojan-panel-ui &&
      rm -rf ${TROJAN_PANEL_UI_DATA}

    docker pull jonssonyan/trojan-panel-ui &&
      docker run -d --name trojan-panel-ui --restart always \
        --network=host \
        -v "${NGINX_CONFIG}":"/etc/nginx/conf.d/default.conf" \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        jonssonyan/trojan-panel-ui

    if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan PanelFront end update complete"
    else
      echo_content red "---> Trojan PanelThe front-end update fails or runs abnormally,Please try to repair or uninstall and reinstall"
    fi
  else
    echo_content skyBlue "---> you installedTrojan PanelAlready the latest version"
  fi
}

# renewTrojan Panel Core
update_trojan_panel_core() {
  # judgmentTrojan Panel CoreWhether to install
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content red "---> please install firstTrojan Panel Core"
    exit 0
  fi

  trojan_panel_core_current_version=$(docker exec trojan-panel-core ./trojan-panel-core -version)
  if [[ -z "${trojan_panel_core_current_version}" || ! "${trojan_panel_core_current_version}" =~ ^v.* ]]; then
    echo_content red "---> The current version does not support automatic updates"
    exit 0
  fi

  echo_content yellow "hint:Trojan Panelkernel(trojan-panel-core)The current version is ${trojan_panel_core_current_version} The latest version is ${trojan_panel_core_latest_version}"

  if [[ "${trojan_panel_core_current_version}" != "${trojan_panel_core_latest_version}" ]]; then
    echo_content green "---> renewTrojan Panel Core"

    read -r -p "Please enter the database'sIPaddress(default:native database): " mariadb_ip
    [[ -z "${mariadb_ip}" ]] && mariadb_ip="127.0.0.1"
    read -r -p "Please enter the port of the database(default:9507): " mariadb_port
    [[ -z "${mariadb_port}" ]] && mariadb_port=9507
    read -r -p "Please enter the database username(default:root): " mariadb_user
    [[ -z "${mariadb_user}" ]] && mariadb_user="root"
    while read -r -p "Please enter the database password(required): " mariadb_pas; do
      if [[ -z "${mariadb_pas}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done
    read -r -p "Please enter a database name(default:trojan_panel_db): " database
    [[ -z "${database}" ]] && database="trojan_panel_db"
    read -r -p "Please enter the user table name of the database(default:account): " account_table
    [[ -z "${account_table}" ]] && account_table="account"

    read -r -p "please enterRedisofIPaddress(default:this machineRedis): " redis_host
    [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
    read -r -p "please enterRedisport(default:6378): " redis_port
    [[ -z "${redis_port}" ]] && redis_port=6378
    while read -r -p "please enterRedispassword for(required): " redis_pass; do
      if [[ -z "${redis_pass}" ]]; then
        echo_content red "password can not be blank"
      else
        break
      fi
    done
    read -r -p "please enterAPIport(default:8100): " grpc_port
    [[ -z "${grpc_port}" ]] && grpc_port=8100

    update__trojan_panel_core_database

    docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

    docker rm -f trojan-panel-core &&
      docker rmi -f jonssonyan/trojan-panel-core

    domain=$(cat "${DOMAIN_FILE}")

    docker pull jonssonyan/trojan-panel-core &&
      docker run -d --name trojan-panel-core --restart always \
        --network=host \
        -v ${TROJAN_PANEL_CORE_DATA}bin/xray/config:${TROJAN_PANEL_CORE_DATA}bin/xray/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/trojango/config:${TROJAN_PANEL_CORE_DATA}bin/trojango/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/hysteria/config:${TROJAN_PANEL_CORE_DATA}bin/hysteria/config \
        -v ${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config:${TROJAN_PANEL_CORE_DATA}bin/naiveproxy/config \
        -v ${TROJAN_PANEL_CORE_LOGS}:${TROJAN_PANEL_CORE_LOGS} \
        -v ${TROJAN_PANEL_CORE_SQLITE}:${TROJAN_PANEL_CORE_SQLITE} \
        -v ${CADDY_CERT}:${CADDY_CERT} \
        -v ${CADDY_SRV}:${CADDY_SRV} \
        -v /etc/localtime:/etc/localtime \
        -e "mariadb_ip=${mariadb_ip}" \
        -e "mariadb_port=${mariadb_port}" \
        -e "mariadb_user=${mariadb_user}" \
        -e "mariadb_pas=${mariadb_pas}" \
        -e "database=${database}" \
        -e "account-table=${account_table}" \
        -e "redis_host=${redis_host}" \
        -e "redis_port=${redis_port}" \
        -e "redis_pass=${redis_pass}" \
        -e "crt_path=${CADDY_CERT}${domain}.crt" \
        -e "key_path=${CADDY_CERT}${domain}.key" \
        -e "grpc_port=${grpc_port}" \
        jonssonyan/trojan-panel-core

    if [[ -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content skyBlue "---> Trojan Panel Coreupdate completed"
    else
      echo_content red "---> Trojan Panel CoreUpdate fails or behaves abnormally,Please try to repair or uninstall and reinstall"
    fi
  else
    echo_content skyBlue "---> you installedTrojan Panel CoreAlready the latest version"
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

# uninstallMariaDB
uninstall_mariadb() {
  # judgmentMariaDBWhether to install
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") ]]; then
    echo_content green "---> uninstallMariaDB"

    docker rm -f trojan-panel-mariadb &&
      rm -rf ${MARIA_DATA}

    echo_content skyBlue "---> MariaDBuninstall complete"
  else
    echo_content red "---> please install firstMariaDB"
  fi
}

# uninstallRedis
uninstall_redis() {
  # judgmentRedisWhether to install
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content green "---> uninstallRedis"

    docker rm -f trojan-panel-redis &&
      rm -rf ${REDIS_DATA}

    echo_content skyBlue "---> Redisuninstall complete"
  else
    echo_content red "---> please install firstRedis"
  fi
}

# uninstallTrojan Panel
uninstall_trojan_panel() {
  # judgmentTrojan PanelWhether to install
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") ]]; then
    echo_content green "---> uninstallTrojan Panel"

    docker rm -f trojan-panel &&
      docker rmi -f jonssonyan/trojan-panel &&
      rm -rf ${TROJAN_PANEL_DATA}

    docker rm -f trojan-panel-ui &&
      docker rmi -f jonssonyan/trojan-panel-ui &&
      rm -rf ${TROJAN_PANEL_UI_DATA} &&
      rm -rf ${NGINX_DATA}

    echo_content skyBlue "---> Trojan Paneluninstall complete"
  else
    echo_content red "---> please install firstTrojan Panel"
  fi
}

# uninstallTrojan Panel Core
uninstall_trojan_panel_core() {
  # judgmentTrojan Panel CoreWhether to install
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") ]]; then
    echo_content green "---> uninstallTrojan Panel Core"

    docker rm -f trojan-panel-core &&
      docker rmi -f jonssonyan/trojan-panel-core &&
      rm -rf ${TROJAN_PANEL_CORE_DATA}

    echo_content skyBlue "---> Trojan Panel Coreuninstall complete"
  else
    echo_content red "---> please install firstTrojan Panel Core"
  fi
}

# uninstall allTrojan Panelrelated container
uninstall_all() {
  echo_content green "---> uninstall allTrojan Panelrelated container"

  docker rm -f $(docker ps -a -q -f "name=^trojan-panel")
  docker rmi -f $(docker images | grep "^jonssonyan/trojan-panel" | awk '{print $3}')
  rm -rf ${TP_DATA}

  echo_content skyBlue "---> uninstall allTrojan PanelThe associated container completes"
}

# ReviseTrojan Panelfront port
update_trojan_panel_ui_port() {
  if [[ -n $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
    echo_content green "---> ReviseTrojan Panelfront port"

    trojan_panel_ui_port=$(grep 'listen.*ssl' ${NGINX_CONFIG} | awk '{print $2}')
    echo_content yellow "hint:Trojan Panelfront end(trojan-panel-ui)The current port is ${trojan_panel_ui_port}"

    read -r -p "please enterTrojan PanelFront-end new port(default:8888): " trojan_panel_ui_port
    [[ -z "${trojan_panel_ui_port}" ]] && trojan_panel_ui_port="8888"
    sed -i "s/listen.*ssl;/listen       ${trojan_panel_ui_port} ssl;/g" ${NGINX_CONFIG} &&
      sed -i "s/https:\/\/\$host:.*\$uri?\$args/https:\/\/\$host:${trojan_panel_ui_port}\$uri?\$args/g" ${NGINX_CONFIG} &&
      docker restart trojan-panel-ui

    if [[ "$?" == "0" ]]; then
      echo_content skyBlue "---> Trojan PanelFront-end port modification completed"
    else
      echo_content red "---> Trojan PanelFront-end port modification failed"
    fi
  else
    echo_content red "---> Trojan PanelThe front end is not installed or is running abnormally,Please repair or uninstall and reinstall and try again"
  fi
}

# to refreshRediscache
redis_flush_all() {
  # judgmentRedisWhether to install
  if [[ -z $(docker ps -a -q -f "name=^trojan-panel-redis$") ]]; then
    echo_content red "---> please install firstRedis"
    exit 0
  fi

  if [[ -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
    echo_content red "---> RedisAbnormal operation"
    exit 0
  fi

  echo_content green "---> to refreshRediscache"

  read -r -p "please enterRedisofIPaddress(default:this machineRedis): " redis_host
  [[ -z "${redis_host}" ]] && redis_host="127.0.0.1"
  read -r -p "please enterRedisport(default:6378): " redis_port
  [[ -z "${redis_port}" ]] && redis_port=6378
  while read -r -p "please enterRedispassword for(required): " redis_pass; do
    if [[ -z "${redis_pass}" ]]; then
      echo_content red "password can not be blank"
    else
      break
    fi
  done

  docker exec trojan-panel-redis redis-cli -h "${redis_host}" -p ${redis_port} -a "${redis_pass}" -e "flushall" &>/dev/null

  echo_content skyBlue "---> RedisCache refresh complete"
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
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-mariadb$") && -z $(docker ps -q -f "name=^trojan-panel-mariadb$" -f "status=running") ]]; then
      echo_content red "---> MariaDBAbnormal operation The log is as follows:"
      docker logs trojan-panel-mariadb
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-redis$") && -z $(docker ps -q -f "name=^trojan-panel-redis$" -f "status=running") ]]; then
      echo_content red "---> RedisAbnormal operation The log is as follows:"
      docker logs trojan-panel-redis
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -z $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
      echo_content red "---> Trojan PanelThe backend is running abnormally The log is as follows:"
      if [[ -f ${TROJAN_PANEL_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_LOGS}trojan-panel.log
      else
        docker logs trojan-panel
      fi
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-ui$") && -z $(docker ps -q -f "name=^trojan-panel-ui$" -f "status=running") ]]; then
      echo_content red "---> Trojan PanelThe front end is running abnormally The log is as follows:"
      docker logs trojan-panel-ui
    fi
    if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -z $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
      echo_content red "---> Trojan Panel CoreAbnormal operation The log is as follows:"
      if [[ -f ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log ]]; then
        tail -n 20 ${TROJAN_PANEL_CORE_LOGS}trojan-panel.log
      else
        docker logs trojan-panel-core
      fi
    fi
  fi
  echo_content green "---> Troubleshooting ended"
}

log_query() {
  while :; do
    echo_content skyBlue "Applications that can query logs are as follows:"
    echo_content yellow "1. Trojan Panel"
    echo_content yellow "2. Trojan Panel Core"
    echo_content yellow "3. quit"
    read -r -p "Please select an application(default:1): " select_log_query_type
    [[ -z "${select_log_query_type}" ]] && select_log_query_type=1

    case ${select_log_query_type} in
    1)
      log_file_path=${TROJAN_PANEL_LOGS}trojan-panel.log
      ;;
    2)
      log_file_path=${TROJAN_PANEL_CORE_LOGS}trojan-panel-core.log
      ;;
    3)
      break
      ;;
    *)
      echo_content red "no such option"
      continue
      ;;
    esac

    read -r -p "Please enter the number of rows to query(default:20): " select_log_query_line_type
    [[ -z "${select_log_query_line_type}" ]] && select_log_query_line_type=20

    if [[ -f ${log_file_path} ]]; then
      echo_content skyBlue "The log is as follows:"
      tail -n ${select_log_query_line_type} ${log_file_path}
    else
      echo_content red "no log file exists"
    fi
  done
}

version_query() {
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel$") && -n $(docker ps -q -f "name=^trojan-panel$" -f "status=running") ]]; then
    trojan_panel_current_version=$(docker exec trojan-panel ./trojan-panel -version)
    echo_content yellow "Trojan Panelrear end(trojan-panel)The current version is ${trojan_panel_current_version} The latest version is ${trojan_panel_latest_version}"
  fi
  if [[ -n $(docker ps -a -q -f "name=^trojan-panel-core$") && -n $(docker ps -q -f "name=^trojan-panel-core$" -f "status=running") ]]; then
    trojan_panel_core_current_version=$(docker exec trojan-panel-core ./trojan-panel-core -version)
    echo_content yellow "Trojan Panelkernel(trojan-panel-core)The current version is ${trojan_panel_core_current_version} The latest version is ${trojan_panel_core_latest_version}"
  fi
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
  echo_content skyBlue "Description: One click Install Trojan Panel server"
  echo_content skyBlue "Author: jonssonyan <https://jonssonyan.com>"
  echo_content skyBlue "Github: https://github.com/trojanpanel"
  echo_content skyBlue "Docs: https://trojanpanel.github.io"
  echo_content red "\n=============================================================="
  echo_content yellow "1. InstallTrojan Panel"
  echo_content yellow "2. InstallTrojan Panel Core"
  echo_content yellow "3. InstallCaddy TLS"
  echo_content yellow "4. InstallMariaDB"
  echo_content yellow "5. InstallRedis"
  echo_content green "\n=============================================================="
  echo_content yellow "6. renewTrojan Panel"
  echo_content yellow "7. renewTrojan Panel Core"
  echo_content green "\n=============================================================="
  echo_content yellow "8. uninstallTrojan Panel"
  echo_content yellow "9. uninstallTrojan Panel Core"
  echo_content yellow "10. uninstallCaddy TLS"
  echo_content yellow "11. uninstallMariaDB"
  echo_content yellow "12. uninstallRedis"
  echo_content yellow "13. uninstall allTrojan Panelrelated applications"
  echo_content green "\n=============================================================="
  echo_content yellow "14. ReviseTrojan Panelfront port"
  echo_content yellow "15. to refreshRediscache"
  echo_content green "\n=============================================================="
  echo_content yellow "16. Fault detection"
  echo_content yellow "17. log query"
  echo_content yellow "18. version query"
  read -r -p "please choose:" selectInstall_type
  case ${selectInstall_type} in
  1)
    install_docker
    install_caddy_tls
    install_mariadb
    install_redis
    install_trojan_panel
    ;;
  2)
    install_docker
    install_caddy_tls
    install_trojan_panel_core
    ;;
  3)
    install_docker
    install_caddy_tls
    ;;
  4)
    install_docker
    install_mariadb
    ;;
  5)
    install_docker
    install_redis
    ;;
  6)
    update_trojan_panel
    ;;
  7)
    update_trojan_panel_core
    ;;
  8)
    uninstall_trojan_panel
    ;;
  9)
    uninstall_trojan_panel_core
    ;;
  10)
    uninstall_caddy_tls
    ;;
  11)
    uninstall_mariadb
    ;;
  12)
    uninstall_redis
    ;;
  13)
    uninstall_all
    ;;
  14)
    update_trojan_panel_ui_port
    ;;
  15)
    redis_flush_all
    ;;
  16)
    failure_testing
    ;;
  17)
    log_query
    ;;
  18)
    version_query
    ;;
  *)
    echo_content red "no such option"
    ;;
  esac
}

main