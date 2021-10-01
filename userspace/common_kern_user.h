/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
	/* add my stuff */
        __u64 rx_tests;
};

struct event {
  __u64 numb1;
  __u64 numb2;
  __u64 numb3;
  __u64 numb4;
  __u64 numb5;
  __u64 numb6;
};

#define ARR_LEN 8
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
