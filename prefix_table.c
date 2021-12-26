#include "prefix_table.h"
#include <stdlib.h>
#include <string.h>

void init_prefix_table(struct prefix_table * table, const struct in6_addr * prefix, uint8_t prefix_len) {
	table->tree = calloc(1, sizeof(struct prefix_tree));
	table->prefix = *prefix;
	table->prefix_len = prefix_len;
}

bool addr_in_prefix(const struct in6_addr *prefix, const struct in6_addr *addr, uint8_t prefix_len) {
	uint8_t bytes = prefix_len / 8;
	for(uint8_t i = 0; i < bytes; i++) {
		if( prefix->s6_addr[i] != addr->s6_addr[i] )
			return false;
	}
	if( prefix_len == 128 )
		return true;
	uint8_t bits = prefix_len % 8;
	uint8_t mask = 0xff << (8-bits);
	return (prefix->s6_addr[bytes] & mask) == (addr->s6_addr[bytes] & mask);
}

struct prefix_tree * get_next_prefix_tree(struct prefix_tree * tree, uint8_t pos, const struct in6_addr * addr, bool create) {
	struct prefix_tree * next;
	uint8_t byte_pos = pos / 8;
	uint8_t mask = 1 << (7 - (pos%8));
	if( addr->s6_addr[byte_pos] & mask )
		next = tree->right.tree;
	else
		next = tree->left.tree;
	if( next == NULL && create ) {
		if( pos < 63 )
			next = calloc(1, sizeof(struct prefix_tree));
		else
			next = calloc(1, sizeof(struct prefix_entry));
		if( addr->s6_addr[byte_pos] & mask )
			tree->right.tree = next;
		else
			tree->left.tree = next;
	}
	return next;
}

void remove_prefix_entry_step(struct prefix_tree * tree, uint8_t pos, const struct in6_addr * addr) {
	struct prefix_tree * next;
	uint8_t byte_pos = pos / 8;
	uint8_t mask = 1 << (7 - (pos%8));
	if( addr->s6_addr[byte_pos] & mask )
		next = tree->right.tree;
	else
		next = tree->left.tree;

	if( pos < 63 ) {
		if( next == NULL )
			return;
		remove_prefix_entry_step(next, pos+1, addr);
		if( next->left.tree == NULL && next->right.tree == NULL ) {
			free(next);
			if( addr->s6_addr[byte_pos] & mask )
				tree->right.tree = NULL;
			else
				tree->left.tree = NULL;
		}
	}
	else {
		struct prefix_entry *entry = (struct prefix_entry *) next;
		free(entry);
		if( addr->s6_addr[byte_pos] & mask )
			tree->right.tree = NULL;
		else
			tree->left.tree = NULL;
	}


}

void add_prefix_entry(struct prefix_table * table, const wg_key key, const struct in6_addr * addr, const struct timespec * last_seen) {
	if( !addr_in_prefix(&table->prefix, addr, table->prefix_len) )
		return;
	struct prefix_tree *tree = table->tree;
	for( int i = table->prefix_len; i < 64; i++ ) {
		tree = get_next_prefix_tree(tree, i, addr, true);
	}
	struct prefix_entry *entry = (struct prefix_entry *) tree;
	memcpy(entry->key, key, 32);
	entry->addr = *addr;
	entry->last_seen = *last_seen;
}

void remove_prefix_entry(struct prefix_table * table, const struct in6_addr * addr) {
	if( !addr_in_prefix(&table->prefix, addr, table->prefix_len) )
		return;
	// keep root
	struct prefix_tree *tree = get_next_prefix_tree(table->tree, table->prefix_len, addr, false);
	if( tree == NULL )
		return;
	remove_prefix_entry_step(tree, table->prefix_len+1, addr);
}

bool get_prefix_entry(const struct prefix_table * table, const struct in6_addr * addr, struct prefix_entry ** entry) {
	if( !addr_in_prefix(&table->prefix, addr, table->prefix_len) )
		return false;
	struct prefix_tree *tree = table->tree;
	for( int i = table->prefix_len; i < 64; i++ ) {
		tree = get_next_prefix_tree(tree, i, addr, false);
		if( tree == NULL )
			return false;
	}
	*entry = (struct prefix_entry *) tree;
	return true;
}

bool _get_prefix_entry_older_than(const struct prefix_tree *tree, uint8_t pos, const struct timespec *time, struct prefix_entry **entry) {
	if( !tree )
		return false;
	if( pos == 63 ) {
		struct prefix_entry *e;
		if( tree->left.data ) {
			e = tree->left.data;
			if( e->last_seen.tv_sec < time->tv_sec
					|| (e->last_seen.tv_sec == time->tv_sec && e->last_seen.tv_nsec < time->tv_nsec) ) {
				*entry = e;
				return true;
			}
		}
		if( tree->right.data ) {
			e = tree->right.data;
			if( e->last_seen.tv_sec < time->tv_sec
					|| (e->last_seen.tv_sec == time->tv_sec && e->last_seen.tv_nsec < time->tv_nsec) ) {
				*entry = e;
				return true;
			}
		}
		return false;
	}
	if( _get_prefix_entry_older_than(tree->left.tree, pos+1, time, entry) )
		return true;
	return _get_prefix_entry_older_than(tree->right.tree, pos+1, time, entry);
}

bool get_prefix_entry_older_than(const struct prefix_table *table, const struct timespec *time, struct prefix_entry **entry) {
	struct prefix_tree *tree = table->tree;
	if( _get_prefix_entry_older_than(tree->left.tree, table->prefix_len+1, time, entry) )
		return true;
	return _get_prefix_entry_older_than(tree->right.tree, table->prefix_len+1, time, entry);
}
