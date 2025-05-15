# name of your application
APPLICATION = ttls_wolfssl

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

# Include packages that pull up and auto-init the link layer.
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and TCP
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += sock_tcp
USEMODULE += sock_udp

# WolfSSL modules
USEPKG += wolfssl
USEMODULE += wolfssl
USEMODULE += wolfssl_tls
USEMODULE += wolfssl_tls13
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_aes
USEMODULE += wolfcrypt_rsa
USEMODULE += wolfcrypt_dh
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfcrypt_sha
USEMODULE += wolfcrypt_md5
USEMODULE += wolfcrypt_hmac
USEMODULE += wolfcrypt_random
USEMODULE += wolfssl_dtls
USEMODULE += wolfssl_psk

# Shell and utils
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ps

# Source files
SRC += main.c
SRC += tls.c

# Timer module
USEMODULE += ztimer
USEMODULE += ztimer_msec

# Network flags
CFLAGS += -DGNRC_TCP

# Debug flags
CFLAGS += -DDEBUG_WOLFSSL
#CFLAGS += -DWOLFSSL_LOG_PRINTF
#CFLAGS += -DWOLFSSL_DEBUG_TLS
#CFLAGS += -DHAVE_IO_TIMEOUT
#CFLAGS += -DTCP_NODELAY
CFLAGS += -Wno-error=unused-variable
CFLAGS += -Wno-error=unused-parameter
CFLAGS += -DGNRC_TCP
CFLAGS += -Wno-error=unused-variable -Wno-error=unused-parameter
CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable

# Comment this out to disable code in RIOT that does safety checking
DEVELHELP ?= 1

# Change this to 0 to show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
