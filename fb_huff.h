/*
 * Lightweight Autonomic Network Architecture
 *
 * Huffman module
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef HUFFMAN_H
#define HUFFMAN_H


#include <linux/spinlock.h>

#define ENGLISH		0
#define EALPHABETSZ	27
#define GERMAN 		1

#define ALPHABETSZ	50

#define MAXDEPTH	10


struct huffman_root {
	struct huffman_node *first;
	rwlock_t tree_lock;
};

struct huffman_node {
	unsigned char character;
	unsigned int frequency;
	struct huffman_node *next[2];
};

struct schedule_node {
    struct schedule_node *next;
    struct huffman_node *huffman;
};

struct language_book {
	unsigned char length;
	unsigned char character[ALPHABETSZ];
	unsigned short frequency[ALPHABETSZ];
};

struct code_book {
	unsigned char alphabetsz;
	unsigned short *code;
	unsigned char *length;
};

#endif /* HUFFMAN_H */
