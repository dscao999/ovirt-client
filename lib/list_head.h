#ifndef LIST_HEAD_DSCAO__
#define LIST_HEAD_DSCAO__
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
#define container_of(ptr, type, member) \
	({ \
	 const typeof(((type *)0)->member) *__mptr = (ptr); \
	 (type *)((char *)__mptr - offsetof(type, member)); \
	 })
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, n, head) \
	    for (pos = (head)->next, n = pos->next; pos != (head); \
			            pos = n, n = pos->next)

#define comp_swap(ptr_dest, oldval, newval) \
	__sync_val_compare_and_swap(ptr_dest, oldval, newval)

struct list_head;
struct list_head {
	struct list_head *prev, *next;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

static inline void INIT_LIST_HEAD(struct list_head *lst)
{
	lst->next = lst;
	lst->prev = lst;
}

static inline void list_add(struct list_head *node, struct list_head *head)
{
	struct list_head *naf = head->prev;

	node->prev = naf;
	node->next = naf->next;
	node->next->prev = node;
	naf->next = node;
}

static inline void list_del(struct list_head *node, struct list_head *head)
{
	struct list_head *prev, *next;

	if (node == head)
		return;
	prev = node->prev;
	next = node->next;
	prev->next = next;
	next->prev = prev;
}

/*static inline struct list_head *list_index(struct list_head *head, int i)
{
	int seq;
	struct list_head *cur;

	seq = -1;
	list_for_each(cur, head) {
		seq++;
		if (seq == i)
			break;
	}
	if (cur == head)
		cur = NULL;
	return cur;
}*/

static inline void lock_unlock(volatile int *lock)
{
	*lock = 0;
}

static inline int lock_lock(volatile int *lock, unsigned int tries)
{
	int i, locked;
	static const struct timespec itv = {.tv_sec = 1, .tv_nsec = 0};

	locked = 0;
	for (i = 0; i < tries + 1; i++) {
		while (i < tries && *lock != 0) {
			nanosleep(&itv, NULL);
			i++;
		}
		if (*lock == 0) {
			locked = __sync_bool_compare_and_swap(lock, 0, 1);
			if (locked)
				break;
		}
	}
	return locked;
}

#ifdef __cplusplus
}
#endif

#endif /* LIST_HEAD_DSCAO__ */
