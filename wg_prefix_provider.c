#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>

#include "wireguard.h"
#include "prefix_table.h"

#define timediff(a, b, result)					\
	do {										\
		result.tv_sec = a.tv_sec - b.tv_sec;	\
		result.tv_nsec = a.tv_nsec - b.tv_nsec;	\
		if (result.tv_nsec < 0) {				\
			--result.tv_sec;					\
			result.tv_nsec += 1000000000L;		\
		}										\
	} while (0)

char *wg_device_name;
struct in6_addr prefix;
uint8_t prefix_len;

struct prefix_table prefix_tab;

bool run = true;

void signal_handler(int sig) {
	if( sig != SIGTERM )
		return;
	run = false;
}

void print_in6_addr(const struct in6_addr * addr) {
	char buffer[40];
	inet_ntop(AF_INET6, addr, buffer, 40);
	printf("%s", buffer);
}

void print_key(wg_key key) {
	wg_key_b64_string b64key;
	wg_key_to_base64(b64key, key);
	printf("%s", b64key);
}

void get_peer(wg_key key, struct wg_allowedip **allowed_ips,  const struct in6_addr * addr) {
	wg_device *device;
	if(wg_get_device(&device, wg_device_name) < 0) {
		printf("Unable to get wg device\n");
		return;
	}

	wg_peer *peer;
	wg_allowedip *allowed_ip;
	bool found = false;
	wg_for_each_peer(device, peer) {
		if( !(peer->flags & WGPEER_HAS_PUBLIC_KEY) )
			continue;
		wg_for_each_allowedip(peer, allowed_ip) {
			if( allowed_ip->family != AF_INET6 )
				continue;
			if( addr_in_prefix( addr, &allowed_ip->ip6, 128 ) ) {
				found = true;
				memcpy( key, peer->public_key, 32 );
				break;
			}
		}
		if( found ) {
			wg_for_each_allowedip(peer, allowed_ip) {
				struct wg_allowedip *new_allowedip = calloc(1, sizeof(wg_allowedip));
				if (!new_allowedip)
					break;
				memcpy( new_allowedip, allowed_ip, sizeof(wg_allowedip) );
				if(!(*allowed_ips)) {
					(*allowed_ips) = new_allowedip;
					(*allowed_ips)->next_allowedip = NULL;
				} else {
					new_allowedip->next_allowedip = (*allowed_ips);
					(*allowed_ips) = new_allowedip;
				}
			}
			break;
		}
	}

	wg_free_device(device);
}

struct in6_addr get_prefix(const struct in6_addr * addr) {
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	struct in6_addr out_addr;
	wg_key key;
	struct wg_allowedip *allowed_ips = NULL;
	get_peer(key, &allowed_ips, addr);
	if( !allowed_ips )
		return out_addr;
	bool found = false;
	for( struct wg_allowedip *aip = allowed_ips; aip; aip = aip->next_allowedip ) {
		if( aip->family != AF_INET6 )
			continue;
		if( addr_in_prefix( &prefix, &aip->ip6, prefix_len ) ) {
			out_addr = aip->ip6;
			struct prefix_entry *entry;
			if( !get_prefix_entry(&prefix_tab, &out_addr, &entry) ) {
				add_prefix_entry(&prefix_tab, key, &out_addr, &now);
				if( !get_prefix_entry(&prefix_tab, &out_addr, &entry) )
					break;
			}
			entry->last_seen = now;
			found = true;
			break;
		}
	}
	if( !found ) {
		uint64_t net = 0;
		uint8_t net_bits = 64-prefix_len;
		for( uint8_t bit = 0; bit < net_bits; bit++ ) {
			uint8_t byte = bit/8;
			uint8_t mask = 1 << (7-(bit%8));
			if( key[byte+1] & mask )
				net |= 1 << bit; 
		}
		bool found_free = false;
		while( !found_free  ) {
			out_addr = prefix;
			for( uint8_t bit = 0; bit < net_bits; bit++ ) {
				uint8_t byte = (bit + prefix_len)/8;
				uint8_t mask = 1 << (7-((bit + prefix_len)%8));
				if( net & (1 << bit) )
					out_addr.s6_addr[byte] |= mask; 
			}
			struct prefix_entry *entry;
			if( get_prefix_entry(&prefix_tab, &out_addr, &entry) ) {
				net++;
				if( net >> net_bits )
					net = 0;
			}
			else {
				found_free = true;
			}
		}
		{
			wg_device device = {0};
			wg_peer peer = {0};
			wg_allowedip allowed_ip = {0};
			strncpy(device.name, wg_device_name, IFNAMSIZ - 1);
			device.name[IFNAMSIZ-1] = '\0';
			device.first_peer = &peer;
			device.last_peer = &peer;

			peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
			memcpy(peer.public_key, key, 32);

			peer.first_allowedip = &allowed_ip;
			allowed_ip.family = AF_INET6;
			allowed_ip.ip6 = out_addr;
			allowed_ip.cidr = 64;
			allowed_ip.next_allowedip = allowed_ips;

			for( struct wg_allowedip *aip = allowed_ips; aip; aip = aip->next_allowedip ) {
				peer.last_allowedip = aip;
			}


			if(wg_set_device(&device) < 0) {
				perror("Unable to set device");
			}
			else {
				add_prefix_entry(&prefix_tab, key, &out_addr, &now);
				printf("new prefix for ");
				print_in6_addr(addr);
				printf(" with key ");
				print_key(key);
				printf(": ");
				print_in6_addr(&out_addr);
				printf("\n");
			}
		}
	}

	{
		struct wg_allowedip *aip = allowed_ips, *next;
		while( aip ) {
			next = aip->next_allowedip;
			free(aip);
			aip = next;
		}
	}
	return out_addr;
}

void * flush_stale_peers(void *) {
	struct timespec time_to_sleep = { .tv_sec = 1, .tv_nsec = 0 };
	struct timespec last_run;
	struct timespec now;
	struct timespec diff;
	clock_gettime(CLOCK_MONOTONIC, &last_run);
	while( run ) {
		do
		{
			nanosleep(&time_to_sleep, NULL);
			clock_gettime(CLOCK_MONOTONIC, &now);
			timediff(now, last_run, diff);
		} while( run && diff.tv_sec < 300 );
		clock_gettime(CLOCK_MONOTONIC, &last_run);

		printf("flushing stale prefixes...\n");

		clock_gettime(CLOCK_REALTIME, &now);

		struct timespec then = now;
		then.tv_sec -= (1*60*60);

		struct prefix_entry *entry;
		while( get_prefix_entry_older_than(&prefix_tab, &then, &entry) ) {
			wg_peer out_peer = {0};
			out_peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
			memcpy(out_peer.public_key, entry->key, 32);

			out_peer.first_allowedip = NULL;
			out_peer.last_allowedip = NULL;

			wg_device *device;
			if(wg_get_device(&device, wg_device_name) < 0) {
				printf("Unable to get wg device\n");
				break;
			}

			wg_peer *peer;
			wg_allowedip *allowed_ip;
			wg_for_each_peer(device, peer) {
				if( !(peer->flags & WGPEER_HAS_PUBLIC_KEY) )
					continue;
				if( memcmp(peer->public_key, entry->key, sizeof(wg_key)) )
					continue;
				wg_for_each_allowedip(peer, allowed_ip) {
					if( allowed_ip->family == AF_INET6 && addr_in_prefix( &entry->addr, &allowed_ip->ip6, 64 ) ) {
						continue;
					}
					struct wg_allowedip *new_allowedip = calloc(1, sizeof(wg_allowedip));
					if (!new_allowedip)
						break;
					memcpy( new_allowedip, allowed_ip, sizeof(wg_allowedip) );
					new_allowedip->next_allowedip = NULL;
					if( !out_peer.first_allowedip )
						out_peer.first_allowedip = new_allowedip;
					if( out_peer.last_allowedip ) {
						out_peer.last_allowedip->next_allowedip = new_allowedip;
					}
					out_peer.last_allowedip = new_allowedip;
				}
			}

			wg_free_device(device);

			wg_device out_device = {0};
			strncpy(out_device.name, wg_device_name, IFNAMSIZ - 1);
			out_device.name[IFNAMSIZ-1] = '\0';
			out_device.first_peer = &out_peer;
			out_device.last_peer = &out_peer;


			printf("removing prefix ");
			print_in6_addr(&entry->addr);
			printf(" from key ");
			print_key(entry->key);
			printf("\n");
			if(wg_set_device(&out_device) < 0) {
				perror("Unable to set device");
			}
			else {
				remove_prefix_entry(&prefix_tab, &entry->addr);
			}
			{
				struct wg_allowedip *aip = out_peer.first_allowedip, *next;
				while( aip ) {
					next = aip->next_allowedip;
					free(aip);
					aip = next;
				}
			}
		}
		printf("done\n");
	}
}

int main(int argc, char **argv) {
	if( argc != 4 ) {
		printf("usage: %s <wg interface> <port> <prefix>\n", argv[0]);
		return 1;
	}

	wg_device_name = argv[1];
	uint16_t port = atoi(argv[2]);

	{
		char * slash = strchr(argv[3], '/');
		if( slash == NULL ) {
			printf("%s has no /\n", argv[3]);
			exit(1);
		}
		*slash = 0;
		if( inet_pton( AF_INET6, argv[3], &prefix) <= 0 ) {
			printf("wrong format: %s\n", argv[3]);
			exit(1);
		}
		prefix_len = atoi(slash+1);
		if(prefix_len >= 64) {
			printf("prefix too small ( > 64 needed)\n");
			exit(1);
		}
	}

	// make output line buffered
	setvbuf(stdout, NULL, _IOLBF, 0);

	init_prefix_table(&prefix_tab, &prefix, prefix_len);
	{
		wg_device *device;
		if(wg_get_device(&device, wg_device_name) < 0) {
			printf("Unable to get wg device\n");
			return 1;
		}

		wg_peer *peer;
		wg_allowedip *allowed_ip;
		wg_key key;
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		wg_for_each_peer(device, peer) {
			wg_for_each_allowedip(peer, allowed_ip) {
				if( allowed_ip->family != AF_INET6 )
					continue;
				if( addr_in_prefix( &prefix, &allowed_ip->ip6, prefix_len ) ) {
					memcpy( key, peer->public_key, 32 );
					add_prefix_entry(&prefix_tab, key, &allowed_ip->ip6, &now);
					break;
				}
			}
		}

		wg_free_device(device);
	}

	int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if( sock < 0) {
		perror("socket");
		return 1;
	}

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(REUSEADDR)");
		exit(1);
	}

	struct sockaddr_in6 bind_addr;
	bind_addr.sin6_family = AF_INET6;
	bind_addr.sin6_port = htons(port);
	bind_addr.sin6_flowinfo = 0;

	size_t wg_device_name_len = strnlen(wg_device_name, IFNAMSIZ);
	struct ifaddrs *ifaddr;
	if( getifaddrs(&ifaddr) != 0 ) {
		perror("getifaddrs");
		exit(1);
	}
	char buffer[40];
	bool found_addr = false;
	for( struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if( ifa->ifa_addr == NULL )
			continue;

		if( strcmp( wg_device_name, ifa->ifa_name ) != 0 )
			continue;

		if( ifa->ifa_addr->sa_family != AF_INET6 )
			continue;

		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) ifa->ifa_addr;

		inet_ntop(AF_INET6, (struct in6_addr *) &addr->sin6_addr, buffer, 40);
		if( strncmp( "fe80::", buffer, 6 ) == 0 ) {
			bind_addr.sin6_addr = addr->sin6_addr;
			found_addr = true;
			break;
		}
	}
	freeifaddrs(ifaddr);
	if( !found_addr ) {
		printf("did not find the fe80:: address of %s\n", wg_device_name);
		exit(1);
	}

	size_t ifidx = if_nametoindex(wg_device_name);
	if( ifidx == 0 ) {
		perror("if_nametoindex");
		exit(1);
	}

	bind_addr.sin6_scope_id = ifidx;

	if( bind( sock, (struct sockaddr*) &bind_addr, sizeof(bind_addr) ) < 0 ) {
		perror("bind");
		exit(1);
	}

	if( listen( sock, 100 ) != 0 ) {
		perror("listen");
		exit(1);
	}

	pthread_t flush_thread;

	{
		int rc = pthread_create( &flush_thread, NULL, &flush_stale_peers, NULL );
		if( rc ) {
			printf("Could not create flush_stale_peers thread\n");
			return 1;
		}
	}

	struct pollfd pollfds[1];
	pollfds[0].fd = sock;
	pollfds[0].events = POLLIN;

	signal(SIGTERM, signal_handler);

	printf("running...\n");

	while( run ) {
		struct sockaddr_in6 addr;
		unsigned int addr_len = sizeof( addr );
		int rc = poll(pollfds, 1, 100);
		if( rc < 0 ) {
			perror("poll");
			run = false;
			break;
		}
		if( rc == 0 )
			continue;
		if( ! pollfds[0].revents & POLLIN )
			continue;
		int fd = accept( sock, (struct sockaddr *)&addr, &addr_len );
		if( fd == -1 ) {
			perror("accept");
			run = false;
			break;
		}

		struct in6_addr prefix = get_prefix(&addr.sin6_addr);
		char buffer[44];
		inet_ntop(AF_INET6, &prefix, buffer, 40);
		strcat(buffer, "/64\n");
		write(fd, buffer, strlen(buffer));
		close(fd);
	}

	close(sock);

	pthread_join( flush_thread, NULL );

	return 0;
}
