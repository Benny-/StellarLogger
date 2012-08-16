/*
 * Reconstruction of the TCP header structure, slightly modified.  With
 * provisions for little- and big-endian architectures.
 */
 
#include <sys/types.h>
#include <cstdint>

#define __BYTE_ORDER __LITTLE_ENDIAN

typedef struct tcp4hdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t	res1:4,
			doff:4,
			fin:1,
			syn:1,
			rst:1,
			psh:1,
			ack:1,
			urg:1,
			res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t	doff:4,
			res1:4,
			res2:2,
			urg:1,
			ack:1,
			psh:1,
			rst:1,
			syn:1,
			fin:1;
#endif
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
} tcp4hdr;
