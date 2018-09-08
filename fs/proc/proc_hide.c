#include <linux/pid_namespace.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include "internal.h"

#define PROC_HIDE_SIZE 16UL

struct proc_hide {
	struct hlist_node node;
	char *entry;
	size_t len;
};

static u32 entry_key_seed;
static DEFINE_HASHTABLE(proc_hide, PROC_HIDE_SIZE);
static DEFINE_SPINLOCK(proc_hide_lock);

static int proc_hide_add(const char *entry, size_t len)
{
	struct proc_hide *new;
	unsigned long hash_key;

	new = kzalloc(sizeof(struct proc_hide), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->entry = kstrndup(entry, len, GFP_KERNEL);
	if (!new->entry) {
		kfree(new);
		return -ENOMEM;
	}

	new->len = len;
	hash_key = jhash(entry, len, entry_key_seed);
	spin_lock(&proc_hide_lock);
	hash_add_rcu(proc_hide, &new->node, hash_key);
	spin_unlock(&proc_hide_lock);

	return 0;
}

static int proc_hide_check(struct proc_dir_entry *de, struct pid_namespace *pid)
{
	struct proc_hide *hide_entry;
	unsigned long entry_hash;

	if (!pid->level)
		return 0;

	entry_hash = jhash(de->name, de->namelen, entry_key_seed);
	spin_lock(&proc_hide_lock);
	hash_for_each_possible_rcu(proc_hide, hide_entry, node, entry_hash) {
		if (strncmp(de->name, hide_entry->entry, de->namelen) == 0) {
			spin_unlock(&proc_hide_lock);
				return 1;
		}
	}
	spin_unlock(&proc_hide_lock);

	return 0;
}

int proc_hide_lookup(struct proc_dir_entry *de, struct inode *inode)
{
	return proc_hide_check(de, proc_pid_ns(inode));
}

int proc_hide_readdir(struct proc_dir_entry *de, struct file *file)
{
	return proc_hide_check(de, proc_pid_ns(file->f_inode));
}

static int proc_hide_show(struct seq_file *sf, void *data)
{
/*
	struct inode *inode = sf->private;
	struct pid_namespace *pid = proc_pid_ns(inode);
*/
	struct proc_hide *hide_entry;
	unsigned long bkt;

	spin_lock(&proc_hide_lock);
	hash_for_each_rcu(proc_hide, bkt, hide_entry, node) {
		seq_printf(sf, "%s\n", hide_entry->entry);
	}
	spin_unlock(&proc_hide_lock);

	return 0;
}

static int proc_hide_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_hide_show, /* inode */ NULL);
}

static ssize_t proc_hide_write(struct file *file, const char __user *buffer,
	size_t count, loff_t *f_pos)
{
	char *kbuf = memdup_user_nul(buffer, count);
	char *pos, *next_line;
	size_t siz;

	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	for (pos = kbuf; pos; pos = next_line) {

		next_line = strchr(pos, '\n');
		if (next_line) {
			siz = next_line - kbuf;

			*next_line = '\0';
			next_line++;
			if (*next_line == '\0')
				next_line = NULL;
		} else siz = count - (kbuf - pos);

		proc_hide_add(pos, siz);
		/* pr_err("Line: '%.*s'\n", (int)siz, pos); */

	}
	kfree(kbuf);

	return count;
}

static const struct file_operations proc_hide_operations = {
	.open		= proc_hide_open,
	.release	= single_release,
	.read		= seq_read,
	.write		= proc_hide_write,
	.llseek		= seq_lseek,
};

static int __init proc_hide_init(void)
{
	struct proc_dir_entry *entry;

	get_random_bytes(&entry_key_seed, sizeof(entry_key_seed));

	hash_init(proc_hide);
	proc_hide_add("hide", 4); /* disabled for all pid namespaces */
	proc_hide_add("version", 7);

	entry = proc_create("hide", 0, NULL, &proc_hide_operations);
	if (!entry)
		return -1;

	return 0;
}
fs_initcall(proc_hide_init);
