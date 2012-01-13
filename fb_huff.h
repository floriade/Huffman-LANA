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
#define MAXALPHABETSZ	255
#define ASCIISZ		128
#define GERMAN 		1

#define ALPHABETSZ	50

#define MAXDEPTH	10

#define HUFF_ENCODE 	0x1234
#define HUFF_DECODE 	0x4321

#define ETH_HDR_LEN	14

#define PROCFS_MAX_SIZE		1024


struct huffman_root {
	struct huffman_node *first;
};

struct huffman_node {
	unsigned char character;
	unsigned int frequency;
	struct huffman_node *next[2];
	struct huffman_node *previous;
};

struct schedule_node {
    struct schedule_node *next;
    struct huffman_node *huffman;
};

struct language_book {
	unsigned char length;
	unsigned char character[ASCIISZ];
	unsigned short frequency[ASCIISZ];
};

struct code_book {
	unsigned char alphabetsz;
	unsigned short *code;
	unsigned char *length;
};

#endif /* HUFFMAN_H */
