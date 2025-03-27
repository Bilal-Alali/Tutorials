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
USEMODULE += sock_tcp

# Add wolfSSL for TLS support
USEPKG += wolfssl
USEMODULE += wolfssl

# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += ps
USEMODULE += log

SRC += main.c
SRC += tls.c

# Timer module
USEMODULE += ztimer
USEMODULE += ztimer_msec

CFLAGS += -DGNRC_TCP
CFLAGS += -Wno-error=unused-variable -Wno-error=unused-parameter

# Enable debug symbols
CFLAGS += -DDEBUG

# Comment this out to disable code in RIOT that does safety checking
DEVELHELP ?= 1

# Change this to 0 to show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include





