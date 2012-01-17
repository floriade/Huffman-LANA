/*
 * Lightweight Autonomic Network Architecture
 *
 * Huffman module.
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/ctype.h>
#include <linux/if_ether.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#include "fb_huff.h"

static unsigned int decode_huffman(struct sk_buff * const skb, char *output, struct huffman_node *node);
static unsigned int encode_huffman(struct sk_buff * const skb, char *output, struct code_book *code_en);

/*char *longword = "Antidisestablishmentarianism";
char longwordencode[64];
char longworddecode[64];*/

/*struct language_book english_book = {EALPHABETSZ, {'0', 'z', 'q', 'x', 'j', 'k', 'v',
					'b', 'p', 'y', 'g', 'f', 'w', 'm', 'u', 'c',
					'l', 'd', 'r', 'h', 's', 'n', 'i', 'o', 'a',
					't', 'e'}, {3, 74, 95, 150, 153, 772, 978, 1492,
					1929, 1974, 2015, 2228, 2360, 2406, 2758, 2782,
					4025, 4253, 5987, 6094, 6327, 6749, 6966, 7507,
					8167, 9056, 12700}};*/

struct language_book english_book = {EALPHABETSZ + 1, {'0', 'z', 'q', 'x', 'j', 'k', 'v',
					'b', 'p', 'y', 'g', 'f', 'w', 'm', 'u', 'c',
					'l', 'd', 'r', 'h', 's', 'n', 'i', 'o', 'a',
					't', 'e', ' '}, {3, 74, 95, 150, 153, 772, 978, 1492,
					1929, 1974, 2015, 2228, 2360, 2406, 2758, 2782,
					4025, 4253, 5987, 6094, 6327, 6749, 6966, 7507,
					8167, 9056, 12700, 14000}};

/*struct language_book english_book = { 86, {'#', '%', '}', '{', '@', '$', '_', 'Z', '/', '[', ']', 'Q', 'K', '&', 'X', '6', '9', '7', '*', '3', '4', '(', ')', 'U', '8', '2', ':', '5', 'J', '1', 'R', 'L', 'G', '0', 'O', 'E', 'P', 'z', 'N', '!', 'F', 'j', 'S', 'Y', 'q', 'H', 'V', 'W', 'B', 'D', 'C', 'x', '\'', 'T', '?', 'A', 'M', ';', '-', 'I', 'k', 'v', '.', 'b', '\"', 'p', 'g', 'y', 'w', 'f', ',', 'c', 'm', '\n', 'u', 'l', 'd', 'r', 'h', 's', 'i', 'n', 'o', 'a', 't', 'e', ' ' },{1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 11, 13, 33, 33, 34, 39, 41, 50, 53, 56, 60, 61, 65, 65, 65, 69, 74, 76, 79, 85, 86, 99, 136, 142, 158, 171, 172, 178, 221, 223, 308, 388, 467, 719, 818, 954, 1140, 1241, 1289, 1512, 1546, 1622, 1688, 1811, 1886, 2031, 2233, 2963, 3397, 4466, 4613, 4637, 4904, 5049, 5795, 5974, 6527, 9654, 15646}};*/

struct fb_huffman_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t tree_lock;
	struct language_book *mybook;
	struct huffman_root *english_first;	/* Huffman Tree */
	struct code_book *code_en;		/* Encoding Table */
};

static int fb_huffman_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int i = 0;
	int drop = 0;
	int newlen = 0;
	unsigned int seq;
	char *decoded, *encoded;
	struct fb_huffman_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock); 
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN || skb_linearize(skb)) {
			drop = 1;	/* skb_linearize(skb) checks if buffer is linear */
			goto err;	/* if not -> linearize. Fail returns != 0 */
		}
	} while (read_seqretry(&fb_priv_cpu->lock, seq));
	//printk(KERN_ERR "Type: 0x%4x\n", ntohs(eth_hdr(skb)->h_proto));
	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xacdc) {	/* temp Fix */
		/* printk(KERN_ERR "HUFF ENCODE detected\n"); */
		if ((encoded = kzalloc(skb->len * 2 * sizeof(char), GFP_ATOMIC)) == NULL) {
			printk(KERN_ERR "Encoding failed!\n");
			goto err;
		}
		read_lock(&fb_priv_cpu->tree_lock);
		//printk(KERN_ERR "Skb len: %d\n", skb->len);
		//printk(KERN_ERR "My len: %d\n", ntohs(*(unsigned short *)(skb->data + ETH_HDR_LEN)));

		if ((newlen = encode_huffman(skb, encoded, fb_priv_cpu->code_en)) == 0) {
			drop = 1;
			goto end;
		}
		/* printk(KERN_ERR "Newlen: %d\n", newlen);
		eth_hdr(skb)->h_proto = htons(skb->len - 14); // Orig. len */

		if (newlen < skb->len) {
			skb_trim(skb, newlen);
		}			
		else if (newlen > skb->len) {
			skb_put(skb, (newlen - skb->len));
		}
		memcpy((skb->data + ETH_HDR_LEN + 2), encoded, newlen - (ETH_HDR_LEN+2));

		/* for (i = 0; i < (skb->len - (ETH_HDR_LEN+2)); i++) {
			printk(KERN_ERR "Skb Data 0x%2x\n", *(skb->data+16+i));
		} */
end:		
		kfree(encoded);
		read_unlock(&fb_priv_cpu->tree_lock);
	}
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xacdc) {
		 printk(KERN_ERR "HUFF DECODE detected!\n"); 
		newlen = ntohs(*(unsigned short *)(skb->data));
		printk(KERN_ERR "Newlen: %d\tSkb->len: %d\n", newlen, skb->len);
		if ((decoded = kzalloc((newlen) * sizeof(char), GFP_ATOMIC)) == NULL) {
			printk(KERN_ERR "Decoding failed!\n");
			goto err;
			}

		for (i = 0; i < (skb->len); i++) {
			printk(KERN_ERR "Skb Data 0x%2x\n", *(skb->data+i));
		}
		read_lock(&fb_priv_cpu->tree_lock);
		/* printk(KERN_ERR "len: %d\n", newlen); */
		decode_huffman(skb, decoded, fb_priv_cpu->english_first->first);
		/*decoded[newlen] = '\0';
		printk(KERN_ERR "Decoded: %s\n", decoded);*/
		newlen += 2; /* 2 Bytes for the length field */

		if (newlen < skb->len)
			skb_trim(skb, newlen);
		else if (newlen > skb->len)
			skb_put(skb, (newlen - skb->len));

		memcpy(skb->data+2, decoded, newlen-2);
		/* *(char *)(skb->data+2+newlen) = '\0';
		printk(KERN_ERR "String %s\n", (skb->data+2)); */

		kfree(decoded);
		read_unlock(&fb_priv_cpu->tree_lock);

	}	
	
	
err:
	if (drop) {
		kfree_skb(skb);
		return PPE_DROPPED;
	}
	return PPE_SUCCESS;
}

static int fb_huffman_event(struct notifier_block *self, unsigned long cmd,
			  void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_huffman_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_huffman_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

#ifdef __DEBUG
	printk("Got event %lu on %p!\n", cmd, fb);
#endif

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_huffman_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (bound)
			printk(KERN_INFO "[%s::%s] port %s bound to IDP%u\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir], msg->idp);
		} break;
	case FBLOCK_UNBIND_IDP: {
		int unbound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_huffman_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::%s] port %s unbound\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir]);
		} break;
	case FBLOCK_SET_OPT: {
		struct fblock_opt_msg *msg = args;
		printk("Set option %s to %s!\n", msg->key, msg->val);
		} break;
	default:
		break;
	}

	return ret;
}

/******************************************************************************
 *	Huffman Encoding/Decoding
 *	Functionality
 *****************************************************************************/

static unsigned char struct_ctor(struct huffman_root *root, struct schedule_node *sched,
				struct code_book *book, unsigned char len)
{
	book->alphabetsz = len;
	if ((book->code = kzalloc(MAXALPHABETSZ * sizeof(unsigned short), GFP_ATOMIC)) == NULL)
		return 0;
	if ((book->length = kzalloc(MAXALPHABETSZ * sizeof(unsigned char), GFP_ATOMIC)) == NULL) {
		kfree(book->code);
		return 0;
	}

	root-> first = NULL;

	sched->huffman = NULL;
	sched->next = NULL;
	return 1;
}

static struct schedule_node *construct_schedule(struct language_book *book,
                                          struct schedule_node *first, struct huffman_node **ptrArray)
{
	int i;
	struct huffman_node *tmphuff;
   	struct schedule_node *tmpsched = NULL;
   	struct schedule_node *tmpschedold = NULL;
	printk(KERN_ERR "Construct schedule start\n");

    	for (i=0;i<book->length;i++) {
        	tmpsched = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
		if (tmpsched == NULL) {
		    printk(KERN_ERR "Schedule Node: Alloc failure.\n");
		    return NULL;
		}
		if (i != 0) { /* next ptr is set after 1st iteration */
			tmpschedold->next = tmpsched;
		}
		else {  
			first->next = tmpsched;
		}	
		tmpsched->huffman = kzalloc(sizeof(struct huffman_node), GFP_ATOMIC);
		if (tmpsched->huffman == NULL) {
		    printk(KERN_ERR "Huffman Node: Alloc failure.\n");
		    return NULL;
		}
		tmphuff = tmpsched->huffman;
		tmphuff->character = book->character[i];
		tmphuff->frequency = book->frequency[i];
		tmphuff->next[0] = NULL;
		tmphuff->next[1] = NULL;
		tmphuff->previous = NULL;
		ptrArray[book->character[i]] = tmphuff;
		tmpschedold = tmpsched;
    	};	
	tmpsched->next = NULL; /* last elem */
	printk(KERN_ERR "Construct schedule finish\n");
    	return tmpsched;
}

/*static void delete_tree(struct huffman_node *node)
{
	struct huffman_node *left, *right;

	if (node == NULL)
		return;
	left = node->next[0];
	right = node->next[1];

	kfree(node);

	delete_tree(left);	// left child 
	delete_tree(right); // right child 
}*/

static void delete_treev2(struct huffman_node *tree)
{
	struct huffman_node *curr, *previous;

	if (tree == NULL) {
		printk(KERN_ERR "Tree is NULL\n");
		return;
	}

	curr = tree;
	previous = curr;

	while (1) {
		if (curr->next[0] != NULL) {
			previous = curr;
			curr = curr->next[0];
		}
		else if (curr->next[1] != NULL) {
			previous = curr;
			curr = curr->next[1];
		}
		else { /* leaf node */
			if (previous->next[0] == NULL)
				previous->next[1] = NULL;
			else
				previous->next[0] = NULL;

			kfree(curr);
			if (curr == tree)
				break;
			curr = tree;
		}
	}
}


static void deconstruct_schedule(struct schedule_node *first)
{
	struct schedule_node *tmpold = NULL;
	struct schedule_node *tmp = first;

	if (first == NULL) {
		printk(KERN_ERR "Deconstruct Schedule: NULL pointer!\n");
		return;
	}
	
	while (1) {
		if(tmp->huffman != NULL)
		    delete_treev2(tmp->huffman);
		tmpold = tmp;
		if(tmp->next != NULL)
			tmp = tmp->next;
		else {
			kfree(tmpold);
			break;
		}
	kfree(tmpold);
	}
}

static void traverse_treev2(struct code_book *code_en, struct huffman_node *node,
			    struct huffman_node **ptrArray)
{
	int i, pos, code;
	char currchar;
	struct huffman_node *curr, *currold;

	for (i = 0; i < MAXALPHABETSZ; i++) {
		if ((curr = ptrArray[i]) == NULL)
			continue;
		currchar = curr->character;		
		pos = 0;
		code = 0;
		while(1) {
			if (curr == node) {
				code_en->length[(unsigned char)currchar] = pos;
				code_en->code[(unsigned char)currchar] = code;
				break;
			}
			currold = curr;
			curr = curr->previous;
			if (curr->next[0] == currold) 
				code += 0<<pos++;
			else 
				code += 1<<pos++;	
		}
	}
}

/*static void traverse_tree(struct code_book *code_en, struct huffman_node *node,
				 unsigned char depth, unsigned short counter)
{
	unsigned short val;
	unsigned short temp;
	unsigned char offset;

	if (node == NULL)
		return;
	if (node->next[0] == NULL && node->next[1] == NULL) {
		offset = (node->character == '\0') ? 0 : 96;
		val = counter>>(MAXDEPTH-depth);
		code_en->code[(node->character) - offset] = val;
		code_en->length[(node->character) - offset] = depth;
	}
		traverse_tree(code_en, node->next[0], depth+1, counter); // left child 
		temp = counter+(1<<((MAXDEPTH -1)-depth));
		traverse_tree(code_en, node->next[1], depth+1, temp); // right child 

}*/

static void insert_schedule_node(struct schedule_node *node,
                           struct schedule_node *tree)
{
	struct schedule_node *tmpold = tree;
	struct schedule_node *tmp = tree->next;

	while (node->huffman->frequency > tmp->huffman->frequency) {
		if (tmp->next == NULL) {    /* was last element */
			tmp->next = node;       /* append new element */
			return;
		}
		tmpold = tmp;
		tmp = tmp->next;		    /* continue search */
	}
    node->next = tmp;               /* insert node */
    tmpold->next = node;
}

static struct huffman_node *extract_huffman_tree(struct schedule_node *first)
{
    struct huffman_node *parent;
    struct huffman_node *ptr;
    struct huffman_node *tmp1, *tmp2;
    struct schedule_node *firstcpy = first->next;
    struct schedule_node *tmp = firstcpy;
    struct schedule_node *head = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
    if (!head)
	return NULL;
    head->huffman = NULL;
    while (tmp != NULL) {           /* at least 2 more elem */
        tmp1 = tmp->huffman;        /* smaller elem */
        tmp2 = tmp->next->huffman;  /* larger elem */
        parent = kzalloc(sizeof(struct huffman_node), GFP_ATOMIC);
        if (parent == NULL) {
            printk(KERN_ERR "Huffman Node: Alloc failure!\n");
            return NULL;
        }
        parent->character = 0;
        parent->next[0] = tmp1;     /* smaller is left */
	tmp1->previous = parent;	
        parent->next[1] = tmp2;     /* larger is right */
	tmp2->previous = parent;
        parent->frequency = tmp1->frequency + tmp2->frequency;
        tmp->next->huffman = parent;/* 2nd sched points to parent now */
        if (firstcpy->next->next == NULL) {	/* schedule tree empty */
        	ptr = tmp->next->huffman;
        	kfree(tmp);
        	kfree(head);
        	return ptr;
        }
        firstcpy = firstcpy->next->next;  /* first points now to 3rd elem*/
        tmp->next->next = NULL;		/* elem is isolated */
        head->next = firstcpy;
        insert_schedule_node(tmp->next, head);
        kfree(tmp);                  /* first elem is freed */
        firstcpy = head->next;
        tmp = firstcpy;
    }
    return NULL;
}

static unsigned char append_code(unsigned short code, unsigned char length, unsigned char free,
					 int *bitstream, unsigned char mod)
{
	unsigned char modulo, leftover;
	int mask, tempbit;
	leftover = (mod != 0) ? mod : length;
	if (unlikely(length > free)) {	/* code & mask (#bits to append), >> to pos */
		mask = (1 << free) -1;
		tempbit = (code >> (length - free)) & mask;
		(*bitstream) = (*bitstream) | tempbit ;
		modulo = length - free;
	}
	else {
		mask = (1 << leftover) -1;
		tempbit = (code & mask) << (free-leftover);
		(*bitstream) = (*bitstream) | tempbit;
		modulo = (free == length) ? 255 : 0;
	}
	return modulo;
}

static unsigned int decode_huffman(struct sk_buff * const skb, char *output,
				 struct huffman_node *node)
{
	unsigned char path;
	unsigned char iteration = 0;
	unsigned short len = ntohs(*(short *)(skb->data));
	unsigned int origlen = len;
	char *tempin = skb->data + 2;
	char *tempout = output;
	int bitstream = *((int *)(tempin));
	struct huffman_node *tmpnode;
	printk(KERN_ERR "Len: %d\n", len);
	printk(KERN_ERR "Bitstream: 0x%8x\n", bitstream);
	//printk(KERN_ERR "Proto:\t%x\n", len);
	while (len-- != 0) {
		tmpnode = node;
		while (tmpnode->next[0] != NULL && tmpnode->next[1] != NULL) {
			path = (bitstream >> (31 - iteration++)) & 0x1;
			tmpnode = tmpnode->next[path];
			if (unlikely(iteration == 32)) {
				tempin += 4;
				bitstream = *((int *)(tempin));
				iteration = 0;
			}
		}
		*tempout++ = tmpnode->character;
		printk(KERN_ERR "Char: %c\n", tmpnode->character);
	}
return origlen;
}

static unsigned int encode_huffman(struct sk_buff * const skb, char *output,
					 struct code_book *code_en)
{

	unsigned char modulo, length;
	unsigned short code;
	unsigned char freebits = 32;
	int bitstream = 0;
	int counter = 0;
	unsigned short len = ntohs(*(unsigned short *)(skb->data + ETH_HDR_LEN));	
	char *tempin = skb->data + ETH_HDR_LEN + 2; /* mac dst/src and eth type */
	char *tempout = output;
	printk(KERN_ERR "Length: %d\n", len);
	for (counter = 0; counter < len; counter++)
		printk(KERN_ERR "Data: %d\t0x%2x\n", counter, *(tempin+counter));	
	counter = 0;
	while ( len-- != 0) {	/* end of string not yet reached */

		/*if (islower(*tempin))
			offset = 96;
		else if (isupper(*tempin))
			offset = 64;
		else
			return 0; */

		code = code_en->code[(unsigned char)*tempin]; // was - offset
		if ((length = code_en->length[(unsigned char)*tempin]) == 0) { // was - offset
			printk(KERN_ERR "Symbol %c not in alphabet!\n", *tempin);
			return 0;
		}
		printk(KERN_ERR "%c -> code: 0x%4x and length: %d\n", *tempin, code, length);
		modulo = append_code(code, length, freebits, &bitstream, 0);
		if (likely(modulo == 0))
			freebits = freebits - length;
		else if (modulo == 255) {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			counter += 4;
			freebits = 32;
			bitstream = 0;
		}
		else {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			counter += 4;
			freebits = 32;
			bitstream = 0;
			append_code(code, length, freebits, &bitstream, modulo);
			freebits = freebits - modulo;
		}
		tempin++;
	}
	/* Endianess Fun! Yay! 

	if (freebits < 8) {
		memcpy(tempout, &bitstream, 4 * sizeof(char));
		counter += 4;
	}
	else if (freebits >= 8 && freebits < 16) {
		endian = bitstream >> 8;
		memcpy(tempout, &endian, 3 * sizeof(char));
		counter += 3;	
	}
	else if (freebits >= 16 && freebits < 24) {
		endian = bitstream >> 16;
		memcpy(tempout, &endian, 2 * sizeof(char));
		counter += 2;
	}
	else if (freebits >= 24 && freebits < 32) {
		endian = bitstream >> 24;
		memcpy(tempout, &endian, 1 * sizeof(char));
		counter += 1;
	}*/

	memcpy(tempout, &bitstream, 4 * sizeof(char));
	counter += 4;
	return counter + ETH_HDR_LEN + 2; /* + MAC HEADER */
//	memcpy(tempout, &bitstream, sizeof(int)); /* copy remaining sequence */
}
/******************************************************************************
 *	Proc fs
 *	Functionality
 *****************************************************************************/

static int fb_huff_proc_show(struct seq_file *m, void *v)
{
	int i = 0;
	struct fblock *fb = (struct fblock *) m->private;
	struct fb_huffman_priv *fb_priv_cpu;
	struct fb_huffman_priv __percpu *fb_priv;
	struct language_book *mybook;

	printk(KERN_ERR "Read detected\n");

	rcu_read_lock();
	fb_priv = (struct fb_huffman_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	/* CPUs share same priv. d */
	rcu_read_unlock();

	read_lock(&fb_priv_cpu->tree_lock);
	mybook = fb_priv_cpu->mybook;
	for (i = 0; i < mybook->length; i++) {
		printk(KERN_ERR "Char:\t%c | Freq:\t%d\n", mybook->character[i], mybook->frequency[i]);
	}
	printk(KERN_ERR "Length:\t%d\n", mybook->length);
	read_unlock(&fb_priv_cpu->tree_lock);
	return 0;
}

static int fb_huff_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fb_huff_proc_show, PDE(inode)->data);
}

static ssize_t fb_huff_proc_write(struct file *file, const char __user * ubuff,
				 size_t count, loff_t * offset)
{
        int len;
	unsigned int cpu;
	char *temp, *oldtemp, *procfs_buffer;
	struct schedule_node *sched_tmp;
	struct huffman_root *english_first_tmp;
	struct code_book *code_en_tmp;
	struct language_book *mybook;
	struct huffman_node **ptrArray;
	struct fb_huffman_priv __percpu *fb_priv;
	struct fb_huffman_priv *fb_priv_cpu;
	int i = 0;
	struct fblock *fb = PDE(file->f_path.dentry->d_inode)->data;

	printk(KERN_ERR "Write detected\n");	// OK1

	rcu_read_lock();							// & 
	fb_priv = (struct fb_huffman_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	// CPUs share same priv. d 
	rcu_read_unlock();							// ¬ 

        if(count > PROCFS_MAX_SIZE) {
		printk(KERN_ERR "Count is too big\n");
                goto ERROR0;
	}
        else
                len = count;
	
	if (!(mybook = kzalloc(sizeof(struct language_book), GFP_ATOMIC))) {
		printk(KERN_ERR "Mybook Alloc failed!\n");
		goto ERROR1;
	}
	if (!(procfs_buffer = kzalloc(PROCFS_MAX_SIZE * sizeof(char), GFP_ATOMIC))) {
		printk(KERN_ERR "Procfs_buffer Alloc failed!\n");
		goto ERROR2;
	}
        if(copy_from_user(procfs_buffer, ubuff, len)) {
		printk(KERN_ERR "Copy_from_user failed!\n");
		goto ERROR3;
        }

        procfs_buffer[len] = '\0';
	temp = procfs_buffer;

	while (*temp != '#') {
		if (*temp == '\n') { /* FIX ME to support newline */
			temp++;
			continue;
		}
		if ((oldtemp = strsep(&temp, ":")) == NULL)
			break;
		printk(KERN_ERR "Oldtemp: %s\n", oldtemp);
		if((i%2) == 0) { // char 
			mybook->character[i/2] = *oldtemp;
		}
		else { // freq 
			mybook->frequency[i/2] = simple_strtoul (oldtemp, (char **) &temp-1, 10);
			if (mybook->frequency[i/2] < 0 || mybook->frequency[i/2] > 65535) {
				printk(KERN_ERR "simple_strtoul failed! Check Input File!\n");
				kfree(mybook);
				goto out;
			}
		}
		if (i++ > MAXALPHABETSZ) {
			printk(KERN_ERR "Error: Alphabet is full\n");
			goto out;
		}
	}

	mybook->length = i/2;	// OK2 
	goto passed;

out:
	write_lock(&fb_priv_cpu->tree_lock);			// & 
	if (fb_priv_cpu->mybook != &english_book)
		kfree(fb_priv_cpu->mybook); // free old book if not english 
	
	get_online_cpus();// & 
	for_each_online_cpu(cpu) {
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		write_seqlock(&fb_priv_cpu->lock); // & 
		fb_priv_cpu->mybook = &english_book;// default 
		write_sequnlock(&fb_priv_cpu->lock);// ¬ 
	}
	put_online_cpus();// ¬ 
	write_unlock(&fb_priv_cpu->tree_lock);			// ¬ 

	kfree(procfs_buffer);
        return len;


passed:
	ptrArray = kzalloc(MAXALPHABETSZ * sizeof(struct huffman_node *), GFP_ATOMIC);
	if(!ptrArray)
		goto out;
	code_en_tmp = kzalloc(sizeof(struct code_book), GFP_ATOMIC);
	if (!code_en_tmp)
		goto erra;	
	english_first_tmp = kzalloc(sizeof(struct huffman_root), GFP_ATOMIC);
	if (!english_first_tmp)
		goto err1;	
	sched_tmp = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
	if (!sched_tmp)
		goto err2;

	if (!struct_ctor(english_first_tmp, sched_tmp, code_en_tmp, mybook->length))
		goto sched_fail;

	if (construct_schedule(mybook, sched_tmp, ptrArray) == NULL) {
		printk(KERN_ERR "Scheduler failed!\n");
		goto sched_fail;
	}
	printk(KERN_ERR "Scheduler passed!\n");

	if ((english_first_tmp->first = extract_huffman_tree(sched_tmp)) == NULL) {
        	printk(KERN_ERR "Tree extraction failed!\n");
        	goto tree_fail;
    }
	printk(KERN_ERR "Tree extracted!\n");

	// traverse_tree(code_en_tmp, english_first_tmp->first, 0, 0);
	traverse_treev2(code_en_tmp, english_first_tmp->first, ptrArray);
	printk(KERN_ERR "Tree traversed!\n");	// OK3

	printk(KERN_ERR "1\n");

	get_online_cpus();// & 
	for_each_online_cpu(cpu) { // 
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu); 
		write_seqlock(&fb_priv_cpu->lock); // &
		write_lock(&fb_priv_cpu->tree_lock);
 
		printk(KERN_ERR "1a\n");// & OK4 (nachfolgend ist der kritische Bereich)
		if (fb_priv_cpu->mybook != &english_book && cpu == 0) { // if not default book delete old book
			printk(KERN_ERR "1b\n");
			kfree(fb_priv_cpu->mybook); // SAFE free old book if not english 
		}
		printk(KERN_ERR "1c\n");
		fb_priv_cpu->mybook = mybook;		// link new book

		if (fb_priv_cpu->english_first != NULL && cpu == 0) {
			printk(KERN_ERR "1d\n");
			delete_treev2(fb_priv_cpu->english_first->first);// delete huff tree
			printk(KERN_ERR "1e\n"); 
			kfree(fb_priv_cpu->english_first);		// delete first node
			printk(KERN_ERR "1f\n");
		}
		fb_priv_cpu->english_first = english_first_tmp; // link new tree

		printk(KERN_ERR "1g\n");
		if (cpu == 0)
			kfree(fb_priv_cpu->code_en);		// delete old code
		printk(KERN_ERR "1h\n"); 
		fb_priv_cpu->code_en = code_en_tmp; 	// link new code
		printk(KERN_ERR "1i\n");
		write_unlock(&fb_priv_cpu->tree_lock); 			// ¬  (Ende des kritischen Bereichs)		
		write_sequnlock(&fb_priv_cpu->lock);// ¬ 
	
	}
	put_online_cpus();// ¬ 
	printk(KERN_ERR "4\n"); 
	printk(KERN_ERR "5\n");
	kfree(sched_tmp);
	kfree(ptrArray);
	kfree(procfs_buffer);
	printk(KERN_ERR "New Alphabet successfully added!\n");
        return len;

tree_fail:
	delete_treev2(english_first_tmp->first);
	goto err2;
sched_fail:
	deconstruct_schedule(sched_tmp);
	kfree(sched_tmp);
	kfree(code_en_tmp->length);
	kfree(code_en_tmp->code);
err2:
	kfree(english_first_tmp);
err1:
	kfree(code_en_tmp);
erra:
	kfree(ptrArray);
	goto out;

ERROR3:
	kfree(procfs_buffer);
	len= -EFAULT;
ERROR2:	
	kfree(mybook);
ERROR1:
	return len;
ERROR0:
	len = -EINVAL;
	return len;
}

static const struct file_operations fb_huff_proc_fops = {
	.owner = THIS_MODULE,
	.open = fb_huff_proc_open,
	.read = seq_read,
	.write = fb_huff_proc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/******************************************************************************
 *	Module Ctor/Dtor/Init/Deinit
 *	Functionality
 *****************************************************************************/

static struct fblock *fb_huffman_ctor(char *name)
{
	int ret = 0;
	unsigned int cpu;
	struct proc_dir_entry *fb_proc;
	struct fblock *fb;
	struct fb_huffman_priv __percpu *fb_priv;
	struct huffman_node **ptrArray;

	struct schedule_node *sched_tmp;
	struct huffman_root *english_first_tmp;
	struct code_book *code_en_tmp;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_huffman_priv);
	if (!fb_priv)
		goto err;
	ptrArray = kzalloc(MAXALPHABETSZ * sizeof(struct huffman_node *), GFP_ATOMIC);
	if(!ptrArray)
		goto err1;
	code_en_tmp = kzalloc(sizeof(struct code_book), GFP_ATOMIC);
	if (!code_en_tmp)
		goto err2;
	english_first_tmp = kzalloc(sizeof(struct huffman_root), GFP_ATOMIC);
	if (!english_first_tmp)
		goto err3;	
	sched_tmp = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
	if (!sched_tmp)
		goto err4;

	if (!struct_ctor(english_first_tmp, sched_tmp, code_en_tmp, english_book.length))
		goto sched_fail;		
	
	//write_lock(&english_first_tmp->tree_lock);

	if (construct_schedule(&english_book, sched_tmp, ptrArray) == NULL) {
		printk(KERN_ERR "Scheduler failed!\n");
		goto sched_fail;
	}
	printk(KERN_ERR "Scheduler passed!\n");

	if ((english_first_tmp->first = extract_huffman_tree(sched_tmp)) == NULL) {
        	printk(KERN_ERR "Tree extraction failed!\n");
        	/* deinitialization */
        	goto tree_fail;
    }

	//traverse_tree(code_en_tmp, english_first_tmp->first, 0, 0);
	traverse_treev2(code_en_tmp, english_first_tmp->first, ptrArray);
	//write_unlock(&english_first_tmp->tree_lock);
	printk("Done!\n");
	/*encode_huffman(code_en_tmp, longword, longwordencode);
	decode_huffman(longwordencode, longworddecode, english_first_tmp->first);
	printk(KERN_ERR "%s\n", longworddecode);*/

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_huffman_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		rwlock_init(&fb_priv_cpu->tree_lock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->code_en = code_en_tmp;
		fb_priv_cpu->english_first = english_first_tmp;
		fb_priv_cpu->mybook = &english_book;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto tree_fail;
	fb->netfb_rx = fb_huffman_netrx;
	fb->event_rx = fb_huffman_event;

	fb_proc = proc_create_data(fb->name, 0444, fblock_proc_dir,
				   &fb_huff_proc_fops,
				   (void *)(long) fb);
	if (!fb_proc)
		goto seclast;

	ret = register_fblock_namespace(fb);
	if (ret)
		goto last;
	kfree(sched_tmp);
	__module_get(THIS_MODULE);
	return fb;

last:
	remove_proc_entry(fb->name, fblock_proc_dir);
seclast:
	cleanup_fblock_ctor(fb);

tree_fail:
	delete_treev2(english_first_tmp->first);
	//write_unlock(&english_first_tmp->tree_lock);
	goto err4;
sched_fail:
	kfree(code_en_tmp->code);
	kfree(code_en_tmp->length);
	deconstruct_schedule(sched_tmp);
	kfree(sched_tmp);
	//write_unlock(&english_first_tmp->tree_lock);
err4:
	kfree(english_first_tmp);
err3:
	kfree(code_en_tmp);
err2:
	kfree(ptrArray);
err1:	
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_huffman_dtor(struct fblock *fb)
{
	struct fb_huffman_priv *fb_priv_cpu;
	struct fb_huffman_priv __percpu *fb_priv;

	rcu_read_lock();
	fb_priv = (struct fb_huffman_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	/* CPUs share same priv. d */
	rcu_read_unlock();

	write_lock(&fb_priv_cpu->tree_lock);
	if (fb_priv_cpu->english_first != NULL) {
		delete_treev2(fb_priv_cpu->english_first->first);	/* delete huff tree */
		kfree(fb_priv_cpu->english_first);	/* delete first node */
	}
	kfree(fb_priv_cpu->code_en->length);	
	kfree(fb_priv_cpu->code_en->code);		
	kfree(fb_priv_cpu->code_en);		/* delete encoding book */
	write_unlock(&fb_priv_cpu->tree_lock);

	free_percpu(rcu_dereference_raw(fb->private_data));
	remove_proc_entry(fb->name, fblock_proc_dir);
	module_put(THIS_MODULE);
}

static struct fblock_factory fb_huffman_factory = {
	.type = "huff",
	.mode = MODE_DUAL,
	.ctor = fb_huffman_ctor,
	.dtor = fb_huffman_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_huffman_module(void)
{
	return register_fblock_type(&fb_huffman_factory);
}

static void __exit cleanup_fb_huffman_module(void)
{
	synchronize_rcu();
	unregister_fblock_type(&fb_huffman_factory);
}

module_init(init_fb_huffman_module);
module_exit(cleanup_fb_huffman_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Florian Deragisch <floriade@ee.ethz.ch>");
MODULE_DESCRIPTION("LANA Huffman module");
