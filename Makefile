LDFLAGS := -lpthread

all: wg_prefix_provider

wg_prefix_provider: wg_prefix_provider.c wireguard.c wireguard.h prefix_table.h prefix_table.c

clean:
	rm *.o wg_prefix_provider
