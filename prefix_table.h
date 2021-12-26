#include "wireguard.h"
#include <time.h>

struct prefix_entry {
	wg_key key;
	struct in6_addr addr;
	struct timespec last_seen;
};

struct prefix_tree {
	union {
		struct prefix_entry *data;
		struct prefix_tree *tree;
	} left;
	union {
		struct prefix_entry *data;
		struct prefix_tree *tree;
	} right;
};

struct prefix_table {
	struct prefix_tree *tree;
	struct in6_addr prefix;
	uint8_t prefix_len;
};

void init_prefix_table(struct prefix_table *, const struct in6_addr *, uint8_t);
bool addr_in_prefix(const struct in6_addr *, const struct in6_addr *, uint8_t);
void add_prefix_entry(struct prefix_table *, const wg_key, const struct in6_addr *, const struct timespec *);
void remove_prefix_entry(struct prefix_table *, const struct in6_addr *);
bool get_prefix_entry(const struct prefix_table *, const struct in6_addr *, struct prefix_entry **);
bool get_prefix_entry_older_than(const struct prefix_table *, const struct timespec *, struct prefix_entry **);
