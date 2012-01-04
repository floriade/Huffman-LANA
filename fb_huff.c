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

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#include "fb_huffman.h"

char *longword = "Antidisestablishmentarianism";
char longwordencode[64];
char longworddecode[64];

struct language_book english_book = {EALPHABETSZ, {'\0', 'z', 'q', 'x', 'j', 'k', 'v',
					'b', 'p', 'y', 'g', 'f', 'w', 'm', 'u', 'c',
					'l', 'd', 'r', 'h', 's', 'n', 'i', 'o', 'a',
					't', 'e'}, {3, 74, 95, 150, 153, 772, 978, 1492,
					1929, 1974, 2015, 2228, 2360, 2406, 2758, 2782,
					4025, 4253, 5987, 6094, 6327, 6749, 6966, 7507,
					8167, 9056, 12700}};

struct fb_huffman_priv {
	idp_t port[2];
	seqlock_t lock;
	struct huffman_root *english_first;	/* Huffman Tree */
	struct code_book *code_en;		/* Encoding Table */
};

static int fb_huffman_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int seq;
	struct fb_huffman_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->lock, seq));
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
				struct code_book *book)
{
	book->alphabetsz = EALPHABETSZ;
	if ((book->code = kzalloc(EALPHABETSZ * sizeof(unsigned short), GFP_ATOMIC)) == NULL)
		return 0;
	if ((book->length = kzalloc(EALPHABETSZ * sizeof(unsigned char), GFP_ATOMIC)) == NULL) {
		kfree(book->code);
		return 0;
	}

	root-> first = NULL;
	rwlock_init(&root->tree_lock);

	sched->huffman = NULL;
	sched->next = NULL;
	return 1;
}

static struct schedule_node *construct_schedule(struct language_book *book,
                                          struct schedule_node *first)
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
		tmpschedold = tmpsched;
    	};	
	tmpsched->next = NULL; /* last elem */
	printk(KERN_ERR "Construct schedule finish\n");
    	return tmpsched;
}

static void delete_tree(struct huffman_node *node)
{
	struct huffman_node *left, *right;

	if (node == NULL)
		return;
	left = node->next[0];
	right = node->next[1];

	kfree(node);

	delete_tree(left);	/* left child */
	delete_tree(right); /* right child */
}

/* To free sub-Huffman tree we need a more complex function */

static void deconstruct_schedule(struct schedule_node *first)
{
    struct schedule_node *tmpold = NULL;
    struct schedule_node *tmp = first;
    while (1) {
        if(tmp->huffman != NULL)
            delete_tree(tmp->huffman);
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

static void traverse_tree(struct code_book *code_en, struct huffman_node *node, unsigned char depth, unsigned short counter)
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
		traverse_tree(code_en, node->next[0], depth+1, counter);	/* left child */
		temp = counter+(1<<((MAXDEPTH -1)-depth));
		traverse_tree(code_en, node->next[1], depth+1, temp); /* right child */

}

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
        parent->next[1] = tmp2;     /* larger is right */
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

static unsigned char append_code(unsigned short code, unsigned char length,
							unsigned char free, int *bitstream,
							unsigned char mod)
{
	unsigned char modulo, leftover;
	int mask, tempbit;
	leftover = (mod != 0) ? mod : length;
	if (unlikely(length > free)) {	/* code & mask (nr of bits to append), shift to position */
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

static void decode_huffman(char *input, char *output, struct huffman_node *node)
{
	unsigned char path;
	unsigned char iteration = 0;
	char lastchar = 1;
	char *tempin = input;
	char *tempout = output;
	int bitstream = *((int *)(tempin));
	struct huffman_node *tmpnode;
	while (lastchar != '\0') {
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
		lastchar = tmpnode->character;
		*tempout++ = lastchar;
	}
}

static void encode_huffman(struct code_book *code_en, char *input, char *output)
{

	unsigned char modulo, offset, length;
	unsigned short code;
	unsigned char freebits = 32;
	int bitstream = 0;
	unsigned char cont = 1;	/* end of text */
	char *tempin = input;
	char *tempout = output;
	while ( cont) {	/* end of string not yet reached */
		if (islower(*tempin))
			offset = 96;
		else if (isupper(*tempin))
			offset = 64;
		else if (*tempin == '\0') {
			offset = 0;
			cont = 0;
		}
		code = code_en->code[(*tempin)-offset];
		length = code_en->length[(*tempin)-offset];
		modulo = append_code(code, length, freebits, &bitstream, 0);
		if (likely(modulo == 0))
			freebits = freebits - length;
		else if (modulo == 255) {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			freebits = 32;
			bitstream = 0;
		}
		else {
			memcpy(tempout, &bitstream, sizeof(int));
			tempout = tempout + 4;
			freebits = 32;
			bitstream = 0;
			append_code(code, length, freebits, &bitstream, modulo);
			freebits = freebits - modulo;
		}
		tempin++;
	}
	memcpy(tempout, &bitstream, sizeof(int)); /* copy ..\n sequence */
}

/******************************************************************************
 *	Module Ctor/Dtor/Init/Deinit
 *	Functionality
 *****************************************************************************/

static struct fblock *fb_huffman_ctor(char *name)
{
	int ret = 0;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_huffman_priv __percpu *fb_priv;

	struct schedule_node *sched_tmp;
	struct huffman_root *english_first_tmp;
	struct code_book *code_en_tmp;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_huffman_priv);
	if (!fb_priv)
		goto err;

	code_en_tmp = kzalloc(sizeof(struct code_book), GFP_ATOMIC);
	if (!code_en_tmp)
		goto err2;
	english_first_tmp = kzalloc(sizeof(struct huffman_root), GFP_ATOMIC);
	if (!english_first_tmp)
		goto err3;	
	sched_tmp = kzalloc(sizeof(struct schedule_node), GFP_ATOMIC);
	if (!sched_tmp)
		goto err4;

	if (!struct_ctor(english_first_tmp, sched_tmp, code_en_tmp))
		goto sched_fail;		
	
	write_lock(&english_first_tmp->tree_lock);

	if (construct_schedule(&english_book, sched_tmp) == NULL) {
		printk(KERN_ERR "Scheduler failed!\n");
		goto sched_fail;
	}
	printk(KERN_ERR "Scheduler passed!\n");

	if ((english_first_tmp->first = extract_huffman_tree(sched_tmp)) == NULL) {
        	printk(KERN_ERR "Tree extraction failed!\n");
        	/* deinitialization */
        	goto tree_fail;
    }

	traverse_tree(code_en_tmp, english_first_tmp->first, 0, 0);
	write_unlock(&english_first_tmp->tree_lock);
	printk("Done!\n");
	encode_huffman(code_en_tmp, longword, longwordencode);
	decode_huffman(longwordencode, longworddecode, english_first_tmp->first);
	printk(KERN_ERR "%s\n", longworddecode);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_huffman_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->code_en = code_en_tmp;
		fb_priv_cpu->english_first = english_first_tmp;
	}
	put_online_cpus();

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto tree_fail;
	fb->netfb_rx = fb_huffman_netrx;
	fb->event_rx = fb_huffman_event;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto last;
	__module_get(THIS_MODULE);
	return fb;

last:
	cleanup_fblock_ctor(fb);

tree_fail:
	delete_tree(english_first_tmp->first);
	write_unlock(&english_first_tmp->tree_lock);
	goto err4;
sched_fail:
	deconstruct_schedule(sched_tmp);
	write_unlock(&english_first_tmp->tree_lock);
err4:
	kfree(english_first_tmp);
err3:
	kfree(code_en_tmp);
err2:	
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

	write_lock(&fb_priv_cpu->english_first->tree_lock);
	delete_tree(fb_priv_cpu->english_first->first);	/* delete huff tree */
	kfree(fb_priv_cpu->english_first);	/* delete first node */
	kfree(fb_priv_cpu->code_en);		/* delete encoding book */
	write_unlock(&fb_priv_cpu->english_first->tree_lock);
	free_percpu(rcu_dereference_raw(fb->private_data));
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
