

#                       ptmalloc下的malloc与free

本文是一篇关于malloc和free机制知识梳理的文章，也是本人目前学习下的对整个机制的理解，因此未来可能会有变动与增加，如果有增加与修改部分，我会特别标识。

如果了解整个ptmalloc机制，其实我们能够发现，整个庞大的体系都是围绕着“速度”与“空间”展开，每一个不同的定义方式与差别稍作思考下其实总能找到这两方面的原因。不由感叹一下，不断追寻本质，而本质的尽头还是算法。

鞭尸：[(3条消息) 浅析堆内存管理_白兰王的博客-CSDN博客](https://blog.csdn.net/u014377094/article/details/123009807?spm=1001.2014.3001.5502)现在看看自己当初写，啥也不是：(

源代码整理（那个手撕源代码的男人🤤）：[(3条消息) glibc下malloc与free的实现原理（二）：malloc函数的实现_RC_diamond_GH的博客-CSDN博客](https://blog.csdn.net/weixin_44215692/article/details/123930658)本篇文章过程性源代码暂不添加，会显得有些臃肿。

github：ptmalloc源代码(https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L3147)



## 回顾ptmalloc的三大基本结构

### 1.malloc_state

即Arena Header，每个thread只含有一个Arena Header。Arena Header包含bins的信息、top chunk以及最后一个remainder chunk等

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;
  /* Flags (formerly in max_fast).  */
  int flags;
  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];
  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;
  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;
  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];
  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];
  /* Linked list */
  struct malloc_state *next;
  /* Linked list for free arenas.  */
  struct malloc_state *next_free;
  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

### 2.malloc_chunk

整个ptmalloc机制下的最小单位，malloc与free实际操纵与分配单元。

```c
struct malloc_chunk {
  /* #define INTERNAL_SIZE_T size_t */
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. 这两个指针只在free chunk中存在*/
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

提到chunk不得不补充关于对齐的机制。

```c
#define request2size(req)         //如果小于minsize会直接返回minsize                                
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             
   MINSIZE :                                                      
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```

我们每一次选择malloc指定大小(req)时都会调用这个宏进行对齐，其返回的才是真正的得到的大小。

> 1、由于chunk的复用，所以只要在用户请求的大小基础上加上SIZE_SZ即可；
> 2、由于最终大小必须是2 * SIZE_SZ对齐，所以要向上对齐；
> 3、根据结果与MINSIZE比较，确定最终大小MINSIZE还是对齐后的计算结果。

MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1，也就是说，64位下其为0xf。

例如request2size(0x10)与(0x8）

计算（0x10+0x8+0xf)&~0xf 结果为0x20，(0x8+0x8+0xf)&~0xf结果为0x10，得到的大小符合我们之前的认知。

### 3.heap_info

main arena不包含此结构，因为main arena不包含多个heap。反之，非main arena可能包含多个heap，多个heap由heap_info进行管理。值得提一嘴的是main arena通过sbrk扩展堆，thread arena通过mmap扩展堆，因此非主线程的堆在mmap地址段。

```c
typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

三大结构关系图

![](C:\Users\MarxICB\Desktop\malloc\v2-cdc4b19aeb0c5bd01d24589c303f5d3b_b.png)

![](C:\Users\MarxICB\Desktop\malloc\v2-d1ef4f85211061232d4397f4929e8e91_b.png)

## fastbin，smallbin，largebin，unsortedbin

libc2.26版本更新tcache机制，在此先不考虑，因为tcache机制实际上是在此基础上添加的。并不会有大的改变。我们会在文章末尾展开讨论。

下图是bin的数量。

![](C:\Users\MarxICB\Desktop\malloc\420rbsdeo2o0.png)

### 1.fastbin

```c
 mfastbinptr fastbinsY[NFASTBINS];
```

我们可以从malloc_state看到，fastbin与其他bins定义时便脱离开，是单独定义。其结构也与bins不同，在搜索与遍历时会有所不同。

这里我先放一下fastbin的搜索相关宏

```c
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
// chunk size=2*size_sz*(2+idx)
// 这里要减2，否则的话，前两个bin没有办法索引到。
#define fastbin_index(sz)                                                     \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

```

size_sz在64位与32位下有所不同，64位下为8字节对齐，32位下为4字节对齐，最简单的一个例子，32位下fastbin最小为16字节，而64为32字节，它们都是4个最小单元（4or8）构成。

这里以64位0x20做举例计算，(0x20>>4)-2=0，对应fastbin[0]。fastbin的存在便是为了加快处理速度，所以只由fd进行相互链接形成单链表，fastbin[0]便是充当fd指向了末尾的chunk。

**这里还有一个需要注意的点**，fastbin在32位下默认支持的最大数据空间为64字节，但实际上最大可以为80字节，步进为8字节，64位下双倍。也就是fastbin最多有10个，下标为0~9，64位也是一样。也即是说，一般默认情况下，根本不会启用10个fastbin。

ptmalloc源码中有这样一个宏

```c
#define set_max_fast(s) \
  global_max_fast = (((s) == 0)                             \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
```

我们可以通过它设置最大的fastbin，换句话说，我们可以设置到底启用几个fastbin。

这里又有疑问了，我们为何要管理fastbin的数量。实际上还是与速度有关。增加fastbin将充分利用fastbin，但是增加了内存的footprint。减少的话将很可能降低分配的速度，毕竟fastbin是单链表结构，也是malloc与free下最先考虑的bin。

### 2.bins

剩余几个chunk都是双链表结构，这是它的搜索方式

```c
typedef struct malloc_chunk *mbinptr;

/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i)                                                          \
    (mbinptr)(((char *) &((m)->bins[ ((i) - 1) * 2 ])) -                      \
              offsetof(struct malloc_chunk, fd))

```

举例说明更为清晰，例如我要寻找unsortedbin，我们将unsortedbin，smallbin，largebin以1-126(**不是从0开始**）进行排序，unsortedbin为1，即i=1，i-1*2计算得到0，但并未结束，还需减去malloc_chunk头与fd的举例，这是为何？其实这里是为了模仿chunk的结构，64位下我们最后得到的地址p是bin[0]-0x10,这么一来，p->fd与p->bk便恰好指向了bin[0]与bin[1]，由此我们也便理解了

为何malloc_state中其的定义为mchunkptr bins[NBINS * 2 - 2]。每个bin对应着两个单位，对应fd，kb，方便我们后续使用双链表进行搜索与遍历。而fastbin为单链表结构，自然定义方式分开了。这里有一张对应关系图：

![](C:\Users\MarxICB\Desktop\malloc\741085_UV2RPUENGAFECNE.jpg)

接下来我们再对smallbin与largebin，unsortedbin进行分析。看看它们有什么独特之处。

#### smallbin

（32位）小于512字节的chunk称之为small chunk，small bin就是用于管理small chunk的。就内存的分配和释放速度而言，small bin比larger bin快，但比fast bin慢。smallbin中，每个bin中chunk的大小都是固定的。

smallbin的范围覆盖了fastbin（在讨论malloc与free时便能理解这种设计了），其和其他bins与fastbin的显著区别还在于，他们的chunk的PREV_INUSE位可变，而fastbin的始终为1。以smallbin为例，如果一个smallchunk在free时，其物理地址前后的chunk已为free状态（此时smallchunk的PREV_INUSE位为0），便会对其进行合并，放入unsortedbin。

注：*PREV_INUSE位(P): 表示前一个chunk是否为allocated。*

#### largebin

比smallbin的大小大的chunk都包含在内。除了与上述smallbin相同的特点外，其每个bin中的chunk大小并不固定

在这63个large bins中，前32个large bin依次以64字节步长为间隔，即第一个large bin中chunk size为512~575字节，第二个large bin中chunk size为576 ~ 639字节。紧随其后的16个large bin依次以512字节步长为间隔；之后的8个bin以步长4096为间隔；再之后的4个bin以32768字节为间隔；之后的2个bin以262144字节为间隔；剩下的chunk就放在最后一个large bin中。

largechunk在bin中也会排序。双链表的 (bin_at)->bk的chunk最小，(bin_at)->fd的chunk最大，遍历时会通过bk先从最小的开始。虽然smallbin的每个bin中chunk大小都相同，但也是通过(bin_at)->bk遍历的，free时则优先从->fd放入，由此可见，bins都遵循FIFO。fastbin则由于依靠fd单链表连接，所以遵循LIFO。

largebin还有一个特点，我们在前面提到过。

```c
/* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
```

largebin中的chunk除了依靠fd，bk相连，还会通过fd_nextsize，bk_nextsize进行连接。语言苍白，图像清晰：

![](C:\Users\MarxICB\Desktop\malloc\741085_Y3GW2FNY36GJEY8.png)

fd_nextsize指针指向下一个较小的chunk们的首chunk，同一大小chunk，只会有一个首chunk来用fd(bk)_nextsize相连。

large bin有两条组织线：和普通的chunk一样通过fd、bk从大到小组织，另一条线就是通过fd_nextsize和bk_nextsize对相同大小的块进行划归，也即是对于相同大小的块，只有第一个块的fd_nextsize和bk_nextsize参与链接，这么做的目的我认为是可以跳掉中间很多不必要的比较，加快对空闲的large chunk的搜索速度！

#### unsortedbin

如其名，unsortedbin与smallbin和largebin有一个显著区别，它只有一个bin，而且其不按largebin的方式进行排序，换言之，其中的chunk没有大小限制（太大另谈），也没有大小顺序，只是依照FIFO，从（bins[0]-gadget)->fd塞入排序。

unsortedbin将会在后面的malloc与free机制中发挥着至关重要的作用。

## malloc机制

实际上，_libc_malloc作为glibc运行库的一员还会调用到api _int_malloc，这才是真正对malloc发挥至关重要的函数。

malloc机制可以由这张图说明

![](C:\Users\MarxICB\Desktop\malloc\741085_4XT7C75WHAHUJJF.jpg)

简而言之，它会优先与fastbin，smallbin进行匹对，如果成功，那么皆大欢喜，如果不行，则会进入大循环。

进入大循环有2条路径：1、请求的堆块为large chunk。2、small bin中对应的那个bin为空(small bin分配失败！)

大循环的主要功能是：

1、将unsorted bin里面所有的chunk都添加到small bin和large bin里面去。走到大循环这一步，说明前面的fastbin已经被合并过并且全部添加到了unsorted bin里面（与malloc_consolidate完成此操作），所以这个时候fastbin是空的！但是在添加的过程中，如果遇到unsorted chunk的大小正好满足用户请求的大小，则直接退出添加过程，并将当前遍历到的chunk返回给用户。last remainder是unsorted chunk整理完了到最后才处理的，满足nb为small chunk这一条件即可从last remainder中分割一块返回给用户，剩下的last remainder继续加入到已经被清空的unsorted bin里面。到了这一步，small chunk请求应该要得到满足了，如果没有得到满足，说明需要到更大的bin里面分配。总之，大循环的第一个功能就是把unsorted chunk重新添加到各个bin，分配堆块只是它顺手完成的工作，当然能分配固然是好事，这样可以省好多事哈哈哈哈！

2、如果用户请求的是large chunk，那么large chunk的分配工作也是在大循环里面完成的。处理完unsorted bin紧接着就是处理large bin。

3、走到第三步说明严格按照用户请求的大小来分配堆块是不可行的，因此要向更大的bin申请堆块。这一步是通过扫描arena里面的binmap来寻找的。（*bitmap[…] 表示bin数组当中某一个下标的bin是否为空，用来在分配的时候加速）

4、如果到这里还没分到堆块，说明所有的bin都没有合适的堆块可以分配，只能向top chunk求救了。如果top chunk大小满足条件可以分割，OK直接从top chunk上切一块下来，剩下的作为新的top chunk。但是如果top chunk太小满足不了请求，只能再回过头到fastbin里面看看还有没有机会了，所以接下来会通过检查arena的have_fastchunk字段来判断fastbin是否为空，如果fastbin不为空，哈哈哈说明还有救，可以继续调用malloc_consolidate函数合并fastbin到unsorted bin，再跳到第1步重新遍历。这里可能会有疑问，fastbin不是前面已经合并过了么，不应该为空么，怎么到这里又有了呢？我的理解是，对于线程堆，可能当前线程睡眠的时候又有其他线程释放堆块到fastbin，对于主线程堆可能就不存在这种情况。

5、最后这里已经没有办法了，向sysmalloc求救。

关于last reminder块，这个块比较特殊，他的字面意思为从一个稍大的chunk割下一部分后剩下的部分。但是通过看代码，只有当割下的那部分是small chunk，那么剩下的才被当做last reminder并且被arena的last_reminder指针所记录。但是不变的是，不管怎么割，最后剩下的总是被放到unsorted bin。

我们从中也是能够看到，遍历unsortedbin的过程中其实就完成了将对其他bin的分类。

## free机制

free机制相对malloc机制来说则少了些（小声嘀咕，除了一些该死的检测）  

上大图！

![](C:\Users\MarxICB\Desktop\malloc\741085_G8KV27T6GUDCWNT.jpg)

不考虑mmap的chunk，普通chunk的释放顺序：

1、如果在fastbin范围内就优先释放到fastbin

2、否则就尝试前后合并合：

   a、并后的chunk靠近top chunk，那就并到top chunk；

   b、合并后的chunk不靠近top chunk，那就放到unsorted bin；

所以free的过程并不和small bin、large bin打交道，只是当malloc的时候，进入到malloc的大循环中处理unsorted bin的时候才会把unsorted bin里面的块按照大小放到smal、large bin里面。

## 补充必要知识点

### consolidate函数

malloc_consolidate函数是一个专门针对fastbins设计的函数，在它执行时，会让被执行的malloc_state中的fastbins所回收的所有chunk都去尝试向上和向下合并其他free chunk，如果合并到了top chunk，这个chunk就直接回归top chunk，如果没有合并到top chunk，那么会加入unsorted bin。

### top chunk 

topchunk的额前一个被使用的flag标志一直都被设置，防止访问前一个内存，在glibc的代码中认为这个chunk永远存在，当他的大小不够的时候会从系统中通过系统调用来分配新的内存，通过brk分配的内存会直接加入top chunk，通过mmap分配的内存会拥有新的heap，当然也拥有了新的top chunk。

### last remainder

malloc_state结构体中的有一个last_remainder成员指针。忘记就翻到前面再看一眼。

当用户请求的是一个small chunk，且该请求无法被small bin、unsorted bin满足的时候，就通过binmaps遍历bin查找最合适的chunk，如果该chunk有剩余部分的话，就将该剩余部分变成一个新的chunk加入到unsorted bin中，另外，再将该新的chunk变成新的last remainder chunk。

对于第一张malloc图哪里的大循环中unsortedbin处理的last remainder必须是仅存的unsorted bin有疑问的话可以这样思考，如果在malloc之前unsorted bin已有多个chunk，假设这时我们在通过largebin分配过以后往unsortedbin放入一个last remainder。这时我们再次malloc，由于FIFO机制，此时一定先遍历非last remainder最后遍历再遍历到它，这样一来，unsorted bin就得到了一次对剩余unsorted chunk的释放。既得到了分配。又得到了空闲空间的释放非常巧妙。

## Tcache

tcache是glibc 2.26(Ubuntu 17.10)之后引入的一种技术，其目的是为了提升堆管理的性能。我们都知道，一旦某个整体的应用添加了更加复杂的执行流程，那么就意味着整体执行的速度就会降低，那么为了弥补这一部分的欠缺，就不得不有所牺牲。所以虽然提升了整体的性能，但却舍弃了很多安全检查，这就意味着更多新的漏洞就伴随而来，也增添了很多利用方式。

tcache引入了两个新的结构体：`tcache_entry`和`tcache_perthread_struct`。增添的两个结构体其实与fastbin有些类似，但是也有一定的区别

tcache_entry结构体如下：

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

```

这里不要被新结构唬住，因为过去如fastbin，对其操作时，如mfastbinptr会指向pre_size位，也就是chunk头，而*tcache_entry则会指向fd位，因此， struct tcache_entry *next其实就是过去的fd位，同样，tcache也是只有fd形成单链表。

tcache_perthread_struct结构体如下：

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

# define TCACHE_MAX_BINS                64

static __thread tcache_perthread_struct *tcache = NULL;

```

- tcache_entry 用单向链表的方式链接了相同大小的处于空闲状态（free 后）的 chunk
- counts 记录了 tcache_entry 链上空闲 chunk 的数目，每条链上最多可以有 7 个 chunk

如果用户需要的chunk_size是non-large chunk的 && tcache已经初始化了 && tcache对应的bin中有相应的chunk块那么调用tcache_get()实现从Tcache中对块进行取出，注意从tcache中取出块是在进入**_int_malloc()之前的** 是在fastbin之前的 是最高级别的一级缓存措施，如下源代码：

```c
// 从 tcache list 中获取内存
  if (tc_idx < mp_.tcache_bins // 由 size 计算的 idx 在合法范围内
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL) // 该条 tcache 链不为空
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  // 进入与无 tcache 时类似的流程
  if (SINGLE_THREAD_P)
    {
      victim = _int_malloc (&main_arena, bytes);
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
              &main_arena == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }

```

free的堆块，当内存小于small bin size时(0x400)，会被优先置入tcache bin链表，当填满七个后，才会填入fastbin/unsortedbin链表。

> 在放入tcache后：
> 先放到对应的tcache中，直到tcache被填满（7个）
> tcache被填满后，接下来再释放chunk，就会直接放进fastbin或者unsorted bin中
> tcache中的chunk不会发生合并，不取消inuse bit

malloc时，优先从tcache bin 中寻找是否有合适大小的bin。

tcache为空后，从bins中找
tcache为空时，如果fastbin、small bin、unsorted bin中有size符合的chunk，会先把fastbin、small bin、unsorted bin中的chunk放到tcache中，直到填满，之后再从tcache中取。这里放一段源码，非常清晰。

```c
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      REMOVE_FB (fb, victim, pp);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
#if USE_TCACHE//可以看到，这里都是后加的
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (pp = *fb) != NULL)
		{
		  REMOVE_FB (fb, tc_victim, pp);
		  if (tc_victim != 0)
		    {
		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

```

需要注意的是，在采用tcache的情况下，只要是bin中存在符合size大小的chunk，那么在重启之前都需要经过tcache一手。并且由于tcache为空时先从其他bin中导入到tcache，所以此时**chunk在bin中和在tcache中的顺序会反过来**。smallbin顺序不会反。

tcache_put()与tcache_get()函数暂先不放了，过程只是单纯的拿与塞，没有其他保护。Tcache机制其实说的有点多了，下次如果做题被折磨导致我再研究研究tcache，可能会再加一些注意事项。

## 保护机制变化梳理

libc2.26增加tcache机制，tcache get,put缺少检测

libc2.27增加tcache double free检测

libc2.29增加unlink检测，检查要释放堆块的prevsize和将要合并的堆块的size是否相等

libc2.32增加检测申请地址是否以0x10对齐，fastbin attack的利用办法受到限制，例如经典的通过错位构造”\x7f”劫持malloc_hook和IO_FILE的利用办法。

这里本意想对不同版本的libc保护变化进行整理，不过目前对相关知识相对欠缺，对比源码需要耗费大量时间与精力。以上变化是目前我所了解的，欢迎补充。至于攻击方式，目前学业不精，未来会再单独整理。

2022.4.3第一次





