CONTIKI_PROJECT = client-node attacker-node root-node
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

MODULES += os/net/routing/rpl-lite
MODULES += os/services/simple-energest

include $(CONTIKI)/Makefile.include
