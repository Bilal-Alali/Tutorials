# Name of your application
APPLICATION = mqtt
# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

# Include packages that pull up and auto-init the link layer.
USEMODULE += auto_init_gnrc_netif
USEMODULE += netdev_default
USEMODULE += gnrc_icmpv6_echo
# Include the shell package for accessing the device over the command line
USEMODULE += shell
# Include the shell commands
USEMODULE += shell_cmds_default
# Include xtimer for timeouts
USEMODULE += ps
USEMODULE += xtimer
# Include IPv6 functionality
USEMODULE += gnrc_ipv6_default
USEMODULE += saul_default
USEPKG += paho-mqtt
USEMODULE += sock_tcp
USEMODULE += ztimer
USEMODULE += ztimer_msec

DEVELHELP ?= 1


# Change this to 0 to enable code in RIOT that uses parts of the C99 standard
# that are not supported by MSVC:
WERROR ?= 1

include $(RIOTBASE)/Makefile.include


DEFAULT_CHANNEL ?= 23

include $(RIOTMAKE)/default-radio-settings.inc.mk

