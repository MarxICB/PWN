# how2heap个人学习总结

## 1.fastbin_dup

double free基本操作

2.27下由于多了tcache，可以先free7个填满tcache再calloc3个后free放入fastbin。calloc与malloc区别除了对语法略有不同，会对内容初始化以外还会跳过tcache直接执行int_malloc。

后续2.31，32，33，34无区别。

## 2.fastbin_dup_into_stack

double free基操，有一点需要注意，fast chunk在获取时会对其大小

进行检测，检查是否符合当前的fastbin。

获取时最后有两个检测check_remalloced_chunk(关于符号位的检测，对PREV_INUSE(P)无检测，所以符号位都为0就可以了），alloc_perturb（暂不知，目前无影响）

拓展：默认采用ATOMIC_FASTBINS搜索，不会产生ABA问题。

## 3.fastbin_dup_consolidate

double free操作，利用malloc 一个largebinchunk 导致 malloc_consolidate(),victim被放至unsortedbin，绕过fastbin double free的检测。

## 4.unsafe_unlink

经典利用unlink函数，检测fd->bk=victim,bk->fd=victim.

利用：p=victim.

fd=p-24,bk=p-16

效果:

p=p-16,p=p-24.

p[3]=sp,p[0]=xx **==**sp=xx

具体实现中，采用了extend方法（如offbynull），注意一点就是例子都是采用的chunk中设fakechunk，原因是p指向的是fd位。

2.23采用fastbin，2.27为了绕过tcache，采用largebin大小。

2.31增加检测，需要设置fakechunk的size

2.32，33，34无差别。

## 5.house_of_spirit

示例为2.23.伪造fastbin再free，但nextsize记得设为合法值。

绕过"The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks

## 6.poison_null_byte

![](C:\Users\MarxICB\Desktop\malloc\how2heap\屏幕截图 2022-04-16 220111.png)

示例2.23.这个有些巧妙，b在free后通过off by one 减小大小，同时设置b里面对应presize位为0x20，过chunksize(P) != prev_siz(next_chunk(P))检测，（原文里说newer versions，咱也不知道那个version，有点不爽）之后malloc两次分割b1，b2，再freeb1和c（c的presize正常）这样实现overlapping。此时就出现了一个小chunkb2存在大chunk的有趣情况。印象里，我们通常用这种方式来实现对main arena位置的泄露。

2.27的话由于tcache，采用了largebin大小。

再看2.31

看一下malloc0x20的图

![](C:\Users\MarxICB\Desktop\malloc\how2heap\屏幕截图 2022-04-16 230733.png)

0x290是tcache的大小。

![](C:\Users\MarxICB\Desktop\malloc\how2heap\屏幕截图 2022-04-16 230905.png)

那个算padding的有些巧妙，0x20中0x10是内容，0x10是下一个chunk的头，当时竟然猪脑过载了，想半天，哭笑不得。

总共分7个步骤

step1: allocate padding

step2: allocate prev chunk and victim chunk

step3: link prev into largebin

这一步有一个非常关键的地方，就是largebin有fd_nextsize和bk_nextsize，其充当了fakechunk的fd和bk，unlink时会用到！

step4: allocate prev again to construct fake chunk

step5: bypass unlinking

step6: add fake chunk into unsorted bin by off-by-null

step7: validate the chunk overlapping

从step6时，其实也可以通过unsorted bin的fd，bk获取main arena的地址。太厉害了这思路。反思一下自己做题，还是会的东西少，导致无从下手，坐着就算原地圆寂了也想不出来。

3.32，33，34同3.31.

不清楚2.31与2.27多了那些检测，初步猜想与被extend的chunk大小和presize检测有关。

## 7.house_of_lore

2.23版本下通过将free状态下smallchunk的bk修改成指定位置后再连续malloc获取指定位置的使用。利用了一下smallbin缺少大小检测。

2.31，32，33，34都采用了栈中创建一个bk链表的方式来进行。

因为2.26后有tcache，无法直接像23一样。通过smallbin连接后，调用时会把smallbinchunk链接入tcache。

疑问来了，为什么要创建bk链表，其实是为了把tcache填满，这里展示一下smallchunk填入tcache的源码

```c
if ((victim = last(bin)) != bin) {
            if (victim == 0) /* initialization check */
                malloc_consolidate(av);
            else {
                bck = victim->bk;
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                set_inuse_bit_at_offset(victim, nb);
                bin->bk = bck;
                bck->fd = bin;

                if (av != &main_arena) set_non_main_arena(victim);
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
            }
        }

```

## 8.overlapping_chunks

通过修改unsorted bin中chunk2的大小完成对chunk3的覆盖。

给了一堆各版本例子，不过没什么特殊差别。

## 9.overlapping_chunks2

与1的不同就是先修改size再free，但要注意size修改时要+prev_in_use位。

## 10.house_of_force

通过修改top chunk的size为-1（特别大）然后再malloc一个bss_var - sizeof(long)*4 - ptr_top的大chunk，再次malloc就可以获取该stack的操作权了。

## 11.unsorted_bin_into_stack

fakechunk的bk指向自己，在unsortedbin中不就成无限套娃了，我理解是循环足够次数后就自己出来了。

## 12.unsorted_bin_attack

就是把victim的bk指向stack-16，从而stack=unsortedbin位置。有个疑问，阅读源码发现结束条件是bk指向自己，chunk从unsortedbin中移除会检测一下size是否正常，可是stack的bk没设值，所以它会去哪里？它会一直遍历unsortedbin，这个是后面直接循环足够次数自己出来？有些疑问。

## 13.large_bin_attack

伪造一个largechunk 的bk和bk_nextsize,减小size，free一个较大chunk，chunk被放置在伪造chunk和largechunk中间，从而修改栈的值。2.23与2.27示例相同。

glibc2.30以后增加两新check

fwd->bk_nextsize->fd_nextsize != fwd

bck->fd != fwd

Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest。

这里最后逻辑思考了一下，想明白了。

p1->bk_nextsize->fd->nextsize=stack

其实正常来说p1的bk_nextsize指向的是largebin的最小chunk,...->fd_nextchunk其实就是最小chunk的fd_nextchunk

贴个源码

```c
if ((unsigned long) (size) <
                        (unsigned long) chunksize_nomask(bck->bk)) {
                        fwd = bck;
                        bck = bck->bk;

                        victim->fd_nextsize = fwd->fd;
                        victim->bk_nextsize = fwd->fd->bk_nextsize;
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
                    }
```

可以看到，如果victim小于最小chunk，直接使用

```c
victim->bk_nextsize = fwd->fd->bk_nextsize;
                        fwd->fd->bk_nextsize =
                            victim->bk_nextsize->fd_nextsize = victim;
```

这里不难理解，从逻辑上也只能通过fwd的fd的bknextsize来找到victim的bknextsize应该填的位置。

至于为何没有检测上述的check，由于我没有多版本的glibc源码的资源，我只能合理猜想一下，fwd->bk可以通过，可是bins上那个伪chunk哪来的bknextsize，肯定按原来的没法检测，所以也就缺失了检测。3.32，33，34都一样。小声：我觉得只要想检测这块，无非就是再加一条check...

## 14.house_of_einherjar

大extend之术，确信。通过off-by-one，把pre is ues位改为0，presize设置一下，甚至直接extend到栈。（注意unlink检测！）

2.23，27给的示例一样，31跟27差的有点大，31先overlapping实现对内部小chunk的fd更改，最后tcache poisoning。那个地方paddingchunk是为了绕过tcache计数检测（在tcache的get中），不过我又看了一下源码，没找到对tcache的chunk的size检测，大概是没有吧。有一点疑惑，31可不可以像27一样利用？示例里并没说增加了那些检测导致不行，存疑。

32版本变态了许多，首先是target必须0x10对齐（aligned，看how2heap天天学英语），how2heap里是这样说的

```c
// due to https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41,
	// it must be properly aligned.
```

还有一个恶心点

```c
d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12);
```

印象里后面版本会对指针加个^=。属实是带恶人了，how2heap最后一个就与它有关。

后面33，34，遛了一遍，应该没啥区别。

## 15.house_of_orange

house 系列噩梦之一了算是。没办法，直面了。

学习的时候发现一个宝藏文章[House of orange - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/218887)需要注意的是这种方法只适用于libc-2.23及之前的版本，2.23之后的版本增加了vtable check，也有办法绕过，但是2.27及之后的版本取消了abort刷新流的操作，所以这个方法基本就失效了。

文章中有这样一段总结，算是非常清晰了**：**house of orange的主要过程就是通过unsorted bin attack修改IO_list_all，但是unsorted bin attack写入的地址不是我们可控的，写入的是main arena+88，所以需要通过某个中间媒介。我们发现在IO_list_all+0x68的位置是chain域（用于链接FILE结构体链表的指针域），然后又发现main arena+88+0x68的位置是smallbin中size=0x60的chunk数组，这个smallbin中0x60的数组中的chunk是我们可以构造的，也就是我们是可控的，所以可以在这里伪造fake file结构体。在house of orange中采用的方法就是将old top chunk的size修改为0x60这样就会被我们链入smallbin的0x60的数组中，同时在old top chunk中构造fake file结构体（就是FSOP中的构造方法），通过执行overflow的if判断（IO_write_base=0,IO_write_ptr=1,mode=0），布置好vtable和system函数，令_IO_file_jumps中overflow的函数指针是system函数，/bin/sh参数的话就布置到fake file结构体的开头，因为调用vtable中函数的时候，会将IO_FILE指针作为函数的参数。

需要注意的是house of orange中由于_mode因随机化有1/2的几率是负数，所以成功几率是1/2.

house of orange中的函数调用流程：

**__libc_malloc** => **malloc_printerr** => **libc_message** => **abort** => **_IO_flush_all_lockp**

malloc_printerr是malloc中用来打印错误的函数，所以house of orange最后getshell的时候前面会有一个报错，显示malloc出错了，这是正常现象

这里是张malloc0x1000后触发brk的内存图

![](C:\Users\MarxICB\Desktop\malloc\how2heap\屏幕截图 2022-04-17 171947.png)

有一点小思考，通过一系列操作后，stdout被设计到了old top chunk，因为调用stdout的overflow后直接getshell了，所以其下一个连接位置其实也不重要。

## 16.house_of_roman

这个利用方式跟平常写题见过的差不多。不过平常会通过偏移找到准确的system/execve。这道题的话则利用malloc不会对内容清理，导致存留原先smallbin的fd，先malloc一个fastbin通过覆盖修改到hook，这里有个15/16的爆破成功几率。第二步的话通过unsortedbin attack修改hook的值，第三步再来个覆盖至system，还是几率调用成功。

下次malloc（“bin/sh”）直接就调用system了。

这种利用方式，目测应该是缺少输出方式，否则直接通过偏移就能找到准确地址了。

## 17.tcache_poisoning

其实就是free俩（绕过数量检测）tcachechunk后修改fd，之后再malloc两次获得目标地址。

2.27，31给的都一样。2.32的tcache增加了一个0x10地址对齐的检测需要绕过，后面更改地址时还要来个12位后的亦或（因为aslr机制下，最后1.5字节是固定的）2.32，33，34看起来与2.31无差。

## 18.tcache_house_of_spirit

给的演示，27到34都一样。这个看起来比上一个还要简单，直接在stack里创建fakechunk，之后free会进入tcache。但是和上一个有个不一样的点，上一个进行的16字节对齐，这个却并没有。好像又是栈对齐问题，有些不清晰，下次找个时间好好调试一下，留的坑总是要填的。

##  19.house_of_botcake

还是蛮简单的，示例2.27，先把tcache填满，然后free a和pre，合并到unsortedbin，malloc一个tcache，之后free a，进入tcache，后面一个简单的tcache_poisoning，但是利用方式完善了。有一点需要注意，pre物理地址在a前，所以a的大小不会更改，free才能名正言顺进tcache。

后面2.32，33，34内容反而减少了一些，没有tcache_poisoning，没送佛送到西......

## 20.tcache_stashing_unlink_attack

挺有意思的一个利用，先把tcache填满，之后再free掉0，2chunk进unsortedbin，之后申请大一些的大小，将0，2放入smallbin，把2的bk指向stack，之后再calloc（calloc不会从tcache找）。导致2和伪chunk都进入tcache。示例标注有个fakechunk的bck->fd=victim的检测需要过。给的2.27-34示例都是一样的。从smallbin放到tcache缺少大小检测。

## 21.fastbin_reverse_into_tcache

并没有演示什么利用，但跟上一个smallbin放入进行了一个对照，就像题目那样reverse，其实反映的是FIFO和FILO的的区别。

## 22.decrypt_safe_linking

这个展示了一下2.32加入的safe linking机制的算法。

```c
	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
```

house_of_mind_fastbin 与house_of_storm有点难，容我换换脑子，改日再更。

