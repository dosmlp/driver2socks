/* OPTIONAL: Pools to replace heap allocation
 * Optional: Pools can be used instead of the heap for mem_malloc. If
 * so, these should be defined here, in increasing order according to
 * the pool element size.
 *
 * LWIP_MALLOC_MEMPOOL(number_elements, element_size)
 */
//#include "lwip/priv/memp_std.h"
//#include "lwipopts.h"
//定义不同大小内存池的数量
#if MEM_USE_POOLS
LWIP_MALLOC_MEMPOOL_START
LWIP_MALLOC_MEMPOOL(100, 256)
LWIP_MALLOC_MEMPOOL(50, 512)
LWIP_MALLOC_MEMPOOL(10, 1024)
LWIP_MALLOC_MEMPOOL(480, 2048)
LWIP_MALLOC_MEMPOOL(80, 4096)
LWIP_MALLOC_MEMPOOL_END
#endif /* MEM_USE_POOLS */

/* Optional: Your custom pools can go here if you would like to use
 * lwIP's memory pools for anything else.
 */
//LWIP_MEMPOOL(SYS_MBOX, 22, 100, "SYS_MBOX")
