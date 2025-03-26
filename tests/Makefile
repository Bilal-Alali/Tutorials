# name of your application
APPLICATION = ttls_wolfssl

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += sock_tcp
USEMODULE += gnrc_ipv6
USEMODULE += sock_tls

# TLS module implementation
# USEMODULE += sock_tls_tcp

# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ps

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfssl
USEMODULE += wolfssl_dtls

# Select public key algorithm (or PSK) support fot ciphersuite(s):
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfcrypt_rsa wolfcrypt_dh
CFLAGS += -Wall
#USEMODULE += wolfssl_psk
#USEMODULE += wolfcrypt_rsa
# Configure wolfSSL (enable TLS 1.2)
#CFLAGS += -DWOLFSSL_TLS13 -DWOLFSSL_TLS12
# Define the necessary options for TLS 1.3
#CFLAGS += -DHAVE_FFDHE_2048
#CFLAGS += -DWC_RSA_PSS

SRC += main.c
SRC += tls.c


# Uncomment the following line to add debug symbols
#CFLAGS+=-g -ggdb3

# Timer module
USEMODULE += ztimer
USEMODULE += ztimer_msec

CFLAGS += -DGNRC_TCP
CFLAGS += -Wno-error=unused-variable -Wno-error=unused-parameter


# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
