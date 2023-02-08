# Mytracer介绍：
Mytracer是一款用于分析Linux内核数据包收发链路的工具，可以快速的打印数据包经过的内核函数以及iptables的表链转发路径，可用于网络延迟、偶发丢包等内核网络异常场景的排查，也可方便内核网络爱好者进行学习与研究。

1. 不需要单独开启iptables trace，即可打印报文经过的iptables表链路径；
2. 跟踪指定的ip地址和端口，即可打印相关的调用栈以及更细粒度的调用函数。
3. 内核网络报文转发对应的函数源码学习

Linux内核数据包收发链路路径图如下：
![Linux 数据包收发内核路径图--0919.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666327164115-a4020fdc-33b5-4741-9232-210952f7e1e7.png#clientId=u75e24528-a37d-4&errorMessage=unknown%20error&from=ui&id=ufc7c7448&name=Linux%20%E6%95%B0%E6%8D%AE%E5%8C%85%E6%94%B6%E5%8F%91%E5%86%85%E6%A0%B8%E8%B7%AF%E5%BE%84%E5%9B%BE--0919.png&originHeight=1495&originWidth=1905&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1569478&status=error&style=none&taskId=u26b185b7-f146-4ff0-a6bc-424be14208c&title=)

## github：
[https://github.com/mYu4N/mytracer](https://github.com/mYu4N/mytracer)
## 安装部署：

1. 需要使用alinux2及以上的系统版本（4.19+），alinux3当时有兼容性问题，正在修复中，修复版本请单独联系我获取
2. 依赖ebpf相关组件，可安装bcctools工具合集
```json
yum install kernel-devel-`uname -r` bcc-tools
```

3. 下载文件mytracer.py 及mytracer.c，置于同目录下，运行 python mytracer.py -h 即可查看详细使用方法。
4. 查看内核函数对应的源码需要安装kernel-debuginfo，建议系统内常备kernel-debuginfo及kernel-devel，然后使用faddr2line工具查找该函数地址对应的代码行号。
```json
yum install kernel-debuginfo-`uname -r`
wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/faddr2line
```

## 使用帮助：
```
 python mytracer.py -h
usage: mytracer.py [-h] [-H IPADDR] [--proto PROTO] [--icmpid ICMPID]
                    [-c CATCH_COUNT] [-P PORT] [-p PID] [-N NETNS]
                    [--dropstack] [--callstack] [--iptable] [--route] [--keep]
                    [-T] [-t]

Trace any packet through TCP/IP stack

optional arguments:
  -h, --help            show this help message and exit
  -H IPADDR, --ipaddr IPADDR
                        ip address
  --proto PROTO         tcp|udp|icmp|any
  --icmpid ICMPID       trace icmp id
  -c CATCH_COUNT, --catch-count CATCH_COUNT
                        catch and print count
  -P PORT, --port PORT  udp or tcp port
  -p PID, --pid PID     trace this PID only
  -N NETNS, --netns NETNS
                        trace this Network Namespace only
  --dropstack           output kernel stack trace when drop packet
  --callstack           output kernel stack trace  --打印全量的调用栈
  --iptable             output iptable path   
  --route               output route path
  --keep                keep trace packet all lifetime
  -T, --time            show HH:MM:SS.ms timestamp (带毫秒的时间戳，已替换为新的格式[2022-10-21 10:32:31.419514 ])
  -t, --timestamp       show timestamp in seconds at us resolution （可以理解是第多少秒，用处不太大）

examples:
      mytracer.py                                     # trace all packets
      mytracer.py --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
      mytracer.py --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
      mytracer.py --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
      mytracer.py -t -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --callstack --icmpid=100 -N 10000


输出结果说明
第一列：ebpf抓取内核事件的时间,支持毫秒级时间戳
第二列：skb当前所在namespace的inode号（可以使用lsns -t net查看对比）
第三列：skb->dev 所指设备（待修复nil的识别）
第四列：抓取事件发生时，数据包目的mac地址
第五列：数据包信息，由4层协议+3层地址信息+4层端口信息组成（T代表TCP，U代表UDP，I代表ICMP，其他协议直接打印协议号）
第六列：数据包的跟踪信息，由skb内存地址+skb->pkt_type+抓取函数名（如果在netfilter抓取，则由pf号+表+链+执行结果构成）
 
第六列，skb->pkt_type含义如下（\include\uapi\linux\if_packet.h）：
/* Packet types */
#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_USER		6		/* To user space	*/
#define PACKET_KERNEL		7		/* To kernel space	*/
/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/
 
第六列，pf号含义如下（\include\uapi\linux\netfilter.h）：
enum {
	NFPROTO_UNSPEC =  0,
	NFPROTO_INET   =  1,
	NFPROTO_IPV4   =  2,
	NFPROTO_ARP    =  3,
	NFPROTO_NETDEV =  5,
	NFPROTO_BRIDGE =  7,
	NFPROTO_IPV6   = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO,
};
```

# mytracer场景展示

## 基于mytracer追踪报文场景模拟:
### 模拟场景1：RST跟踪

- 模拟场景：访问pod的非法监听地址导致报文被目标端reset
- 分析手段：分别使用tcpdump、tcpdrop以及mytracer跟踪数据库分析定位
- 请求端：集群内跨节点访问（非pod所在节点）,本模拟场景中为192.168.88.154 
- 目的端：访问指定pod不存在的端口，本模拟场景的pod地址为  192.168.40.230：8080
- 抓包点：目的端host
- 容器环境：ACK terway-eniip ipvlan
```
# kubectl get pods -o wide my-gotools-5bc6dfcd75-j4tmk 
NAME                          READY   STATUS    RESTARTS   AGE   IP               NODE                      NOMINATED NODE   READINESS GATES
my-gotools-5bc6dfcd75-j4tmk   1/1     Running   6          10d   192.168.40.230   cn-beijing.192.168.0.17   <none>           <none>
# kubectl exec -it my-gotools-5bc6dfcd75-j4tmk  -- bash
bash-5.1# netstat -antpl
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
bash-5.1# 
```
#### 基础抓包工具tcpdump
在访问不存在的端口的模拟场景中，tcpdump抓包可以看到目标端reset的报文，但是看无法直观的定位到RST根因。
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666233645895-4ed5418c-0a72-49fa-9972-fad2acdedcce.png#clientId=uac1f7f0f-0e76-4&errorMessage=unknown%20error&from=paste&height=376&id=t9ML2&name=image.png&originHeight=752&originWidth=2816&originalType=binary&ratio=1&rotation=0&showTitle=false&size=585744&status=error&style=none&taskId=u90132a85-55fd-4df8-9417-5e3e80fa772&title=&width=1408)
#### bcctools的tcpdrop 
[tcpdrop](https://www.brendangregg.com/blog/2018-05-31/linux-tcpdrop.html)通过监听tcp_drop函数调用来回显，可以显示源目数据包的详细信息，以及内核中TCP 会话状态、TCP报头标志和导致丢包的内核堆栈跟踪。但是访问不存在的端口被RST并非tcp_drop这个函数来拒绝的，因此基于tcp_drop函数的tcpdrop无法追踪到。
/usr/share/bcc/tools/tcpdrop 抓到的流及函数路径
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666233590684-004e9fad-58ee-4718-ba2d-92892b7075c4.png#clientId=uac1f7f0f-0e76-4&errorMessage=unknown%20error&from=paste&height=451&id=ub7455b34&name=image.png&originHeight=902&originWidth=1946&originalType=binary&ratio=1&rotation=0&showTitle=false&size=353794&status=error&style=none&taskId=u32d446f3-2474-4980-8610-6f51d74952a&title=&width=973)
上面drop的包多，过滤下源ip的方式看依然没有想要看到的8080的访问
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666233681221-562fc8c9-1b9e-4faf-8aff-47be1d889f3c.png#clientId=uac1f7f0f-0e76-4&errorMessage=unknown%20error&from=paste&height=483&id=ub998ea1e&name=image.png&originHeight=966&originWidth=1992&originalType=binary&ratio=1&rotation=0&showTitle=false&size=419853&status=error&style=none&taskId=u29c55c09-28ca-4995-8970-0a859d06c66&title=&width=996)

#### 基于mytracer.py的跟踪：
使用mytracer的默认参数去跟踪指定的ip地址和端口即可打印相关的调用栈信息，默认是没有扩展出来具体的调用函数路径的，不过默认的调用函数信息无法直观显示哪一步函数发送的RST。
```
# python mytracer.py --proto=tcp -H 192.168.88.154 -P 8080
time       NETWORK_NS   INTERFACE    DEST_MAC     PKT_INFO                                 TRACE_INFO
[2022-11-04 10:26:26.103401 ][4026531992] eth1         00163e0cb838 T_SYN:192.168.88.154:34060->192.168.40.230:8080 ffff9fdef19eb600.0:napi_gro_receive
[2022-11-04 10:26:26.103676 ][4026531992] eth1         00163e0cb838 T_SYN:192.168.88.154:34060->192.168.40.230:8080 ffff9fdef19eb600.0:__netif_receive_skb
[2022-11-04 10:26:26.103790 ][4026533234] eth0         00163e0cb838 T_SYN:192.168.88.154:34060->192.168.40.230:8080 ffff9fdef19eb600.0:ip_rcv
[2022-11-04 10:26:26.103900 ][4026533234] eth0         00163e0cb838 T_SYN:192.168.88.154:34060->192.168.40.230:8080 ffff9fdef19eb600.0:ip_rcv_finish
[2022-11-04 10:26:26.104033 ][4026533234] nil          6573223a2031 T_ACK,RST:192.168.40.230:8080->192.168.88.154:34060 ffff9fdef19eb700.0:ip_output
[2022-11-04 10:26:26.104196 ][4026533234] eth0         6573223a2031 T_ACK,RST:192.168.40.230:8080->192.168.88.154:34060 ffff9fdef19eb700.0:ip_finish_output
[2022-11-04 10:26:26.104322 ][4026533234] eth0         6573223a2031 T_ACK,RST:192.168.40.230:8080->192.168.88.154:34060 ffff9fdef19eb700.0:__dev_queue_xmit
[2022-11-04 10:26:26.104443 ][4026531992] eth1         eeffffffffff T_ACK,RST:192.168.40.230:8080->192.168.88.154:34060 ffff9fdef19eb700.0:__dev_queue_xmit
```
注（本模拟场景非terway-ipvlan模式）：
1，我们可以看到有多个网卡出现，即使terway+ipvlan的模式，入方向不绕开eth0的协议栈，以及inode号4026531992对应的就是系统本身的网络ns
2，如果是ipvlan的pod，切换到pod内部去访问被iptables拒绝的ip地址，则会直通，即ipvlan的出方向不受iptables影响，直通底层，非ipvlan则受影响
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1667529964965-f561620c-6a0a-4202-882c-c19ad51985ec.png#clientId=ue4e3aeb0-27ac-4&from=paste&height=868&id=oRYWV&name=image.png&originHeight=868&originWidth=2368&originalType=binary&ratio=1&rotation=0&showTitle=false&size=482870&status=done&style=none&taskId=u6a782d4d-db53-4583-8c82-f5db4aee926&title=&width=2368)

可以使用mytracer的--callstack的参数将每一条调用栈都详细打印出来,这个参数的开销比默认参数开销会大一些，但是更有利于问题的排查(为了缩减篇幅，只保留最后一个syn 以及第一个rst)

```
# python mytracer.py --proto=tcp -H 192.168.88.154 -P 8080 --callstack
time       NETWORK_NS   INTERFACE    DEST_MAC     PKT_INFO                                 TRACE_INFO
.......
[2022-11-04 10:35:04.538548 ][4026533234] eth0         00163e0cb838 T_SYN:192.168.88.154:36454->192.168.40.230:8080 ffff9fdef19ea900.0:ip_rcv_finish
    ip_rcv_finish+0x1
    ip_rcv+0x3d
    __netif_receive_skb_one_core+0x42
    netif_receive_skb_internal+0x34
    napi_gro_receive+0xbf
    receive_buf+0xee
    virtnet_poll+0x137
    net_rx_action+0x266
    __softirqentry_text_start+0xd1
    irq_exit+0xd2
    do_IRQ+0x54
    ret_from_intr+0x0
    cpuidle_enter_state+0xcb
    do_idle+0x1cc
    cpu_startup_entry+0x5f
    start_secondary+0x197
    secondary_startup_64+0xa4
[2022-11-04 10:35:04.539035 ][4026533234] nil          6173683a3834 T_ACK,RST:192.168.40.230:8080->192.168.88.154:36454 ffff9fdef19ea200.0:ip_output
    ip_output+0x1
    ip_send_skb+0x15
    ip_send_unicast_reply+0x2c5
    tcp_v4_send_reset+0x3c6     #从tcp_v4_rcv的函数上进到send_reset函数地址+0x3c6 ，发送了reset
    tcp_v4_rcv+0x6d3            #tcp接收参数,这里要注意，走到了这个函数的0x6d3地址， 去调用的reset，所以先看这个函数
    ip_local_deliver_finish+0x9c
    ip_local_deliver+0x42
    ip_rcv+0x3d
    __netif_receive_skb_one_core+0x42
    netif_receive_skb_internal+0x34
    napi_gro_receive+0xbf
    receive_buf+0xee
    virtnet_poll+0x137
    net_rx_action+0x266
    __softirqentry_text_start+0xd1
    irq_exit+0xd2
    do_IRQ+0x54
    ret_from_intr+0x0
    cpuidle_enter_state+0xcb
    do_idle+0x1cc
    cpu_startup_entry+0x5f
    start_secondary+0x197
    secondary_startup_64+0xa4
...
```

从这个调用栈里我们可以看到是server端直接拒绝的请求（syn，ack rst），那么怎么看出来是什么原因拒绝的呢？是没监听还是别的原因呢？我们重点看第一次出现rst的函数路径
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1667530116746-3341ab32-da82-42e8-b071-44f96c19bf0f.png#clientId=ue4e3aeb0-27ac-4&from=paste&height=127&id=ue9945523&name=image.png&originHeight=127&originWidth=877&originalType=binary&ratio=1&rotation=0&showTitle=false&size=39268&status=done&style=none&taskId=u9daa5fea-e3fb-42e3-bcb9-5c45ffaa1a0&title=&width=877)
对于很多同学来说，怎么看tcp_v4_rcv+0x6d3 跟  tcp_v4_send_reset+0x3c6是个比较头疼的问题，我之前写过一篇linux内核网络的数据发送，基于dropwatch对函数+偏移量做计算的方式，比较复杂,我们今天使用更简单的方式来找内核代码。
需要安装kernel-debuginfo查看内核函数对应的源码，建议系统内常备kernel-debuginfo及kernel-devel，然后使用faddr2line工具查找该函数地址对应的代码行号。
```
yum install -y kernel-debuginfo.x86_64
wget https://raw.githubusercontent.com/torvalds/linux/master/scripts/faddr2line

# bash faddr2line /usr/lib/debug/lib/modules/4.19.91-26.5.al7.x86_64/vmlinux tcp_v4_send_reset+0x3c6
tcp_v4_send_reset+0x3c6/0x590:
tcp_v4_send_reset at net/ipv4/tcp_ipv4.c:780

# bash faddr2line /usr/lib/debug/lib/modules/4.19.91-26.5.al7.x86_64/vmlinux tcp_v4_rcv+0x6d3
tcp_v4_rcv+0x6d3/0xfc0:
__xfrm_policy_check2 at include/net/xfrm.h:1200
(inlined by) xfrm_policy_check at include/net/xfrm.h:1207
(inlined by) xfrm4_policy_check at include/net/xfrm.h:1212
(inlined by) tcp_v4_rcv at net/ipv4/tcp_ipv4.c:1833
```
##### 内核函数源代码分析：
callstack从下往上看，我们先看tcp send reset的调用方，tcp_rcv的调用链路
如下tcp_v4_rcv函数中，__inet_lookup_skb没有找到监听套接口，跳转到no_tcp_socket标签处.
如果此触发报文的checksum没有问题，将回复Reset报文。
另外在函数tcp_v4_send_reset中会检查当前报文是否设置了reset标志位，不对接收到的reset报文回复reset报文
```

----------tcp_rcv
tcp_v4_rcv at net/ipv4/tcp_ipv4.c:1833

lookup:
	sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source,
			       th->dest, sdif, &refcounted);
	if (!sk)
		goto no_tcp_socket; 找不到socket（监听，session）直接跳到 no_tcp_socket 

  1832  no_tcp_socket:
  1833          if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
  1834                  goto discard_it;
  1835
  1836          tcp_v4_fill_cb(skb, iph, th);
  1837
  1838          if (tcp_checksum_complete(skb)) {checksum的校验
  1839  csum_error:
  1840                  __TCP_INC_STATS(net, TCP_MIB_CSUMERRORS);
  1841  bad_packet:
  1842                  __TCP_INC_STATS(net, TCP_MIB_INERRS);
  1843          } else {
  1844                  tcp_v4_send_reset(NULL, skb);调用tcp_v4_send_reset函数发送reset
  1845          }
  1846
  1847  discard_it:
  1848          /* Discard frame. */
  1849          kfree_skb(skb);
  1850          return 0;

调用tcp_v4_send_reset函数后直接跳转到780行
------tcp_v4_send_reset at net/ipv4/tcp_ipv4.c:780
   650  static void tcp_v4_send_reset(const struct sock *sk, struct sk_buff *skb)
   651  {
   652          const struct tcphdr *th = tcp_hdr(skb);
   653          struct {
   654                  struct tcphdr th;
   655  #ifdef CONFIG_TCP_MD5SIG
   656                  __be32 opt[(TCPOLEN_MD5SIG_ALIGNED >> 2)];
   657  #endif
   658          } rep;
   659          struct ip_reply_arg arg;
   660  #ifdef CONFIG_TCP_MD5SIG
   661          struct tcp_md5sig_key *key = NULL;
   662          const __u8 *hash_location = NULL;
   663          unsigned char newhash[16];
   664          int genhash;
   665          struct sock *sk1 = NULL;
   666  #endif
   667          struct net *net;
   668          struct sock *ctl_sk;
   669
   670          /* Never send a reset in response to a reset. */
   671          if (th->rst)
   672                  return;
   673
   674          /* If sk not NULL, it means we did a successful lookup and incoming
   675           * route had to be correct. prequeue might have dropped our dst.
   676           */
   677          if (!sk && skb_rtable(skb)->rt_type != RTN_LOCAL)
   678                  return;
   679
   680          /* Swap the send and the receive. */
   681          memset(&rep, 0, sizeof(rep));
   682          rep.th.dest   = th->source;
   683          rep.th.source = th->dest;
   684          rep.th.doff   = sizeof(struct tcphdr) / 4;
   685          rep.th.rst    = 1;
   686
   687          if (th->ack) {
   688                  rep.th.seq = th->ack_seq;
   689          } else {
   690                  rep.th.ack = 1;
   691                  rep.th.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
   692                                         skb->len - (th->doff << 2));
   693          }
   694
   695          memset(&arg, 0, sizeof(arg));
   696          arg.iov[0].iov_base = (unsigned char *)&rep;
   697          arg.iov[0].iov_len  = sizeof(rep.th);
   698
   699          net = sk ? sock_net(sk) : dev_net(skb_dst(skb)->dev);
   700  #ifdef CONFIG_TCP_MD5SIG
   701          rcu_read_lock();
   702          hash_location = tcp_parse_md5sig_option(th);
   703          if (sk && sk_fullsock(sk)) {
   704                  key = tcp_md5_do_lookup(sk, (union tcp_md5_addr *)
   705                                          &ip_hdr(skb)->saddr, AF_INET);
   706          } else if (hash_location) {
   707                  /*
   708                   * active side is lost. Try to find listening socket through
   709                   * source port, and then find md5 key through listening socket.
   710                   * we are not loose security here:
   711                   * Incoming packet is checked with md5 hash with finding key,
   712                   * no RST generated if md5 hash doesn't match.
   713                   */
   714                  sk1 = __inet_lookup_listener(net, &tcp_hashinfo, NULL, 0,
   715                                               ip_hdr(skb)->saddr,
   716                                               th->source, ip_hdr(skb)->daddr,
   717                                               ntohs(th->source), inet_iif(skb),
   718                                               tcp_v4_sdif(skb));
   719                  /* don't send rst if it can't find key */
   720                  if (!sk1)
   721                          goto out;
   722
   723                  key = tcp_md5_do_lookup(sk1, (union tcp_md5_addr *)
   724                                          &ip_hdr(skb)->saddr, AF_INET);
   725                  if (!key)
   726                          goto out;
   727
   728
   729                  genhash = tcp_v4_md5_hash_skb(newhash, key, NULL, skb);
   730                  if (genhash || memcmp(hash_location, newhash, 16) != 0)
   731                          goto out;
   732
   733          }
   734
   735          if (key) {
   736                  rep.opt[0] = htonl((TCPOPT_NOP << 24) |
   737                                     (TCPOPT_NOP << 16) |
   738                                     (TCPOPT_MD5SIG << 8) |
   739                                     TCPOLEN_MD5SIG);
   740                  /* Update length and the length the header thinks exists */
   741                  arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
   742                  rep.th.doff = arg.iov[0].iov_len / 4;
   743
   744                  tcp_v4_md5_hash_hdr((__u8 *) &rep.opt[1],
   745                                       key, ip_hdr(skb)->saddr,
   746                                       ip_hdr(skb)->daddr, &rep.th);
   747          }
   748  #endif
   749          arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
   750                                        ip_hdr(skb)->saddr, /* XXX */
   751                                        arg.iov[0].iov_len, IPPROTO_TCP, 0);
   752          arg.csumoffset = offsetof(struct tcphdr, check) / 2;
   753          arg.flags = (sk && inet_sk_transparent(sk)) ? IP_REPLY_ARG_NOSRCCHECK : 0;
   754
   755          /* When socket is gone, all binding information is lost.
   756           * routing might fail in this case. No choice here, if we choose to force
   757           * input interface, we will misroute in case of asymmetric route.
   758           */
   759          if (sk) {
   760                  arg.bound_dev_if = sk->sk_bound_dev_if;
   761                  if (sk_fullsock(sk))
   762                          trace_tcp_send_reset(sk, skb);
   763          }
   764
   765          BUILD_BUG_ON(offsetof(struct sock, sk_bound_dev_if) !=
   766                       offsetof(struct inet_timewait_sock, tw_bound_dev_if));
   767
   768          arg.tos = ip_hdr(skb)->tos;
   769          arg.uid = sock_net_uid(net, sk && sk_fullsock(sk) ? sk : NULL);
   770          local_bh_disable();
   771          ctl_sk = *this_cpu_ptr(net->ipv4.tcp_sk);
   772          if (sk)
   773                  ctl_sk->sk_mark = (sk->sk_state == TCP_TIME_WAIT) ?
   774                                     inet_twsk(sk)->tw_mark : sk->sk_mark;
   775          ip_send_unicast_reply(ctl_sk,
   776                                skb, &TCP_SKB_CB(skb)->header.h4.opt,
   777                                ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
   778                                &arg, arg.iov[0].iov_len);
   779
   780          ctl_sk->sk_mark = 0; 修改sk_mark为0
   781          __TCP_INC_STATS(net, TCP_MIB_OUTSEGS); 记录监控数据到out发送以及outreset的计数 
   782          __TCP_INC_STATS(net, TCP_MIB_OUTRSTS); 这俩计数netstat st看不到，对于的是在/proc/net/snmp
   783          local_bh_enable();
   784
   785  #ifdef CONFIG_TCP_MD5SIG
   786  out:
   787          rcu_read_unlock();
   788  #endif
   789  }

```
##### 分析总结：
走到 no_tcp_socket的路径，基本只有以下几种情况：

1. session已经不存在，被回收了，比如说旧版本的内核twbucket满了，被直接回收掉，如果还有网络请求过来就会reset
2. 监听本身不存在（本案例测试时为curl不存在的端口）

/* 以下信息摘抄自网络
_调用tcp_v4_send_reset发送RESET报文：_

1. _TCP接收报文：在tcp_v4_rcv，如果校验和有问题，则发送RESET；_
2. _TCP接收报文：在tcp_v4_rcv，如果 __inet_lookup_skb 函数找不到报文所请求的socket，则发送RESET；_
3. _TCP收到SYN，发送SYN-ACK，并开始等待连接最后的ACK：在tcp_v4_do_rcv - tcp_v4_hnd_req - tcp_check_req，如果TCP报文头部包含RST，或者包含序列不合法的SYN，则发送RESET；_
4. _TCP收到连接建立最后的ACK，并建立child套接字后：tcp_v4_do_rcv - tcp_child_process - tcp_rcv_state_process - tcp_ack 函数中，如果发现连接等待的最后ACK序列号有问题： before(ack, prior_snd_una)，则发送RESET；_
5. _TCP在ESTABLISH状态收到报文，在tcp_v4_do_rcv - tcp_rcv_established - tcp_validate_incoming 函数中，如果发现有SYN报文出现在当前的接收窗口中： th->syn && !before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)，则发送RESET；_
6. _TCP在进行状态迁移时：tcp_rcv_state_process -_
- _如果此时socket处于LISTEN状态，且报文中含有ACK，则发送RESET;_
- _如果此时socket处于FIN_WAIT_1或者FIN_WAIT_2；当接收已经shutdown，并且报文中有新的数据时，发送RESET；_
- _如果测试socket处于FIN_WAIT_1；=待续=_

__在iptables规则中数据包被拒：_

- _send_reset：在iptables规则中，可以指定 -j RESET。如果符合iptables规则并丢弃数据包，并向对端发送RESET报文；_

以上信息摘抄自网络*/
### 模拟场景2：跟踪iptables丢包：

- 场景模拟：在容器节点上插入一条拒绝访问集群外指定公网ip地址的规则，让系统内访问指定地址被拒绝。
```
# iptables -t filter -I OUTPUT 1 -m tcp --proto tcp --dst 140.205.60.46/32 -j DROP
```

- 排查手段：tcpdump/iptables/mytracer的iptable参数
- 请求端：容器集群节点或者节点上运行的pod
- 目的端：公网IP， 本模拟环境中访问 140.205.60.46。
- 抓包点位：请求发起端所在的节点
- 容器环境：ACK terway-eniip ipvlan

注意：出方向访问非集群内的ip资源,eni模式是直通底层，因此terway-eni + ipvlan的pod 往外访问时不受主机上的iptables规则影响，istiosidecar单加iptables的形式例外

#### 基础抓包工具tcpdump 
iptables丢包场景是无法在tcpdmp抓到报文的。
```
在node eth0上访问: curl 140.205.60.46
# tcpdump -i any host 140.205.60.46 -nv -x
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes

```
为什么抓不到报文？我们回到文章开头的位置看下内核网络的路径图就可以看出，出方向的报文，iptables是在抓包点之前的，如果在iptables的表链上丢掉了报文，则tcpdump无法抓到对应的网络报文，因为报文还没送到抓包点就被丢弃了。
#### 查看iptables表链
如果数据包量小且已经怀疑是iptable丢包的话，也可以直接使用iptables的统计信息查看，如下所示，可以看到output的第一条规则 drop的增长：
```
# iptables -t filter -L OUTPUT  --line-number -n -v
Chain OUTPUT (policy ACCEPT 51 packets, 26067 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1        8   480 DROP       tcp  --  *      *       0.0.0.0/0            140.205.60.46        tcp

# iptables -t filter -L OUTPUT  --line-number -n -v
Chain OUTPUT (policy ACCEPT 51 packets, 26067 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1        9   540 DROP       tcp  --  *      *       0.0.0.0/0            140.205.60.46        tcp
```
#### 基于mytracer追踪：
如下所示，在请求节点上抓取140.205.60.46这个地址的iptable的表链，可以看到时间、ns的inode号、网卡、mac地址、tcpflags  、五元组信息以及iptable表链信息，可以看到syn包丢包点位在filter.OUTPUT.DROP ：
```
curl 140.205.60.46
# python mytracer.py  --proto tcp --iptable -H 140.205.60.46
time       NETWORK_NS   INTERFACE    DEST_MAC     PKT_INFO                                 TRACE_INFO
[15:43:03 ][4026531992] nil          0d0000000000 T_SYN:192.168.0.17:47645->140.205.60.46:80 ffff9935587cbcf8.0:2.raw.OUTPUT.ACCEPT 
[15:43:03 ][4026531992] nil          0d0000000000 T_SYN:192.168.0.17:47645->140.205.60.46:80 ffff9935587cbcf8.0:2.mangle.OUTPUT.ACCEPT 
[15:43:03 ][4026531992] nil          0d0000000000 T_SYN:192.168.0.17:47645->140.205.60.46:80 ffff9935587cbcf8.0:2.nat.OUTPUT.ACCEPT 
[15:43:03 ][4026531992] nil          0d0000000000 T_SYN:192.168.0.17:47645->140.205.60.46:80 ffff9935587cbcf8.0:2.filter.OUTPUT.DROP 

```
为什么我不抓取dropstack？iptables的drop能不能使用dropstack、callstack看到呢？以及说监听不存在的reset算不算dropstack：
```
# python mytracer.py  --proto tcp --callstack -H 140.205.60.46
time       NETWORK_NS   INTERFACE    DEST_MAC     PKT_INFO                                 TRACE_INFO
# python mytracer.py  --proto tcp --dropstack -H 140.205.60.46
time       NETWORK_NS   INTERFACE    DEST_MAC     PKT_INFO                                 TRACE_INFO
```
使用iptables拒绝的访问，抓不到dropstack的信息，换成callstack也不可以，原因在于dropstack监控的是kfree_skb，如果是案例1的场景，没监听的reset直接调用reset参数拒绝的，没走kfree_skb也是dropstack抓不到，但是没监听的访问是可以通过callstack抓到信息的，
```
[2022-10-21 11:06:41.209742 ][4026531992] eth1         eeffffffffff T_ACK,RST:192.168.40.230:8080->192.168.88.154:34454 ffff993508ce2300.0:__dev_queue_xmit
    __dev_queue_xmit+0x1
    ipvlan_queue_xmit+0x20b
    ipvlan_start_xmit+0x16
    dev_hard_start_xmit+0xa4
    __dev_queue_xmit+0x722
    ip_finish_output2+0x1f5
    ip_output+0x61
    ip_send_skb+0x15
    ip_send_unicast_reply+0x2c5
    tcp_v4_send_reset+0x3c6
    tcp_v4_rcv+0x6d3
    ip_local_deliver_finish+0x9c
    ip_local_deliver+0x42


drop_stack只采集kfree_skb的相关信息

#if __BCC_dropstack
int kprobe____kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct event_t event = {};

    if (do_trace_skb(&event, ctx, skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_DROP;
    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, __func__+8, FUNCNAME_MAX_LEN);
    get_stack(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
#endif
```

去掉iptable拒绝访问的规则，执行mytracer看iptables的路径,对比正常访问的调用栈
```
# iptables -t filter -L OUTPUT --line-number
Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    DROP       tcp  --  anywhere             140.205.60.46              tcp
2    ACCEPT     udp  --  169.254.20.10        anywhere             udp spt:domain
3    ACCEPT     tcp  --  169.254.20.10        anywhere             tcp spt:domain
4    CILIUM_OUTPUT  all  --  anywhere             anywhere             /* cilium-feeder: CILIUM_OUTPUT */
5    KUBE-FIREWALL  all  --  anywhere             anywhere            

# iptables -t filter -D OUTPUT  1
```
执行mytracer查看eth0的iptables的路径：
```
# python mytracer.py  --proto tcp --iptable -H 140.205.60.46|grep eth0
[15:44:43 ][4026531992] eth0         000000000000 T_SYN:192.168.0.17:48789->140.205.60.46:80 ffff9935587ca4f8.0:2.mangle.POSTROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         000000000000 T_SYN:192.168.0.17:48789->140.205.60.46:80 ffff9935587ca4f8.0:2.nat.POSTROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,SYN:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2a00.0:2.raw.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,SYN:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2a00.0:2.mangle.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,SYN:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2a00.0:2.mangle.INPUT.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,SYN:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2a00.0:2.filter.INPUT.ACCEPT 
[15:44:43 ][4026531992] eth0         ff005c90ff34 T_ACK:192.168.0.17:48789->140.205.60.46:80 ffff9934c50d2f00.0:2.mangle.POSTROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         bd78ffffff48 T_ACK,PSH:192.168.0.17:48789->140.205.60.46:80 ffff9935587ca8f8.0:2.mangle.POSTROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.raw.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.mangle.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.mangle.INPUT.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.filter.INPUT.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,PSH:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.raw.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,PSH:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.mangle.PREROUTING.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,PSH:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.mangle.INPUT.ACCEPT 
[15:44:43 ][4026531992] eth0         00163e0c327b T_ACK,PSH:140.205.60.46:80->192.168.0.17:48789 ffff9934c50d2500.0:2.filter.INPUT.ACCEPT 
换成堆栈信息,可以看到已经能抓到了
# python mytracer.py  --proto tcp --callstack -H 140.205.60.46
......
[15:45:45 ][4026531992] eth0         000000000000 T_ACK:192.168.0.17:49501->140.205.60.46:80 ffff993496607500.0:__dev_queue_xmit
    __dev_queue_xmit+0x1
    ip_finish_output2+0x1f5
    ip_output+0x61
    __ip_queue_xmit+0x151
    __tcp_transmit_skb+0x582
    tcp_fin+0x14f
    tcp_data_queue+0x51d
    tcp_rcv_state_process+0x3ed
    tcp_v4_do_rcv+0x5b
    tcp_v4_rcv+0xc0c
    ip_local_deliver_finish+0x9c
    ip_local_deliver+0x42
    ip_rcv+0x3d
    __netif_receive_skb_one_core+0x42
    netif_receive_skb_internal+0x34
    napi_gro_receive+0xbf
    receive_buf+0xee
    virtnet_poll+0x137
    net_rx_action+0x266
    __softirqentry_text_start+0xd1
    irq_exit+0xd2
    do_IRQ+0x54
    ret_from_intr+0x0
    cpuidle_enter_state+0xcb
    do_idle+0x1cc
    cpu_startup_entry+0x5f
    start_secondary+0x197
    secondary_startup_64+0xa4
```

### 模拟场景3: 分析网络延迟问题（网卡）

- 模拟场景：借助tc命令行工具，给指定网卡注入延迟来模拟server端返回慢的场景
- 分析手段：使用mytracer来看下如何分析网络延迟
- 目的端（服务端）： 注入延迟300ms的的pod：192.168.88.27 。
- 请求端：可访问通pod地址即可（本环境为192.168.0.17）
- 抓包点位：目的端

我们挑选一个pod登录到对应的主机上，同时切换到该pod的net namespace里面，使用tc设置300ms的延迟看下效果，tc添加的延迟，是作用于出方向的，本案例将延迟设置在server端（即pod）
```
添加300ms的延迟
# tc qdisc add dev eth0 root netem delay 300ms
删除的话把add换成del即可
# tc qdisc del dev eth0 root netem delay 300ms

```
新开一个客户端测试curl，可以看到延迟已经加成功了。
```
# time curl -I 192.168.88.27 
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 24 Oct 2022 08:49:18 GMT
Content-Type: text/html
Content-Length: 10671
Last-Modified: Mon, 08 Aug 2022 06:31:21 GMT
Connection: keep-alive
ETag: "62f0adb9-29af"
Accept-Ranges: bytes


real    0m0.609s
user    0m0.003s
sys     0m0.003s
```
额外的问题：为什么加了300ms延迟，curl回显是0.6秒呢？
#### tcpdump抓包
单纯从抓包看，慢在了server端。
server端切换ns并抓包：
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666602048279-f8e7232a-6103-4c74-acee-3f87fdd9249b.png#clientId=ub3bce9d4-8e4c-4&from=paste&height=105&id=ud6b3a44e&name=image.png&originHeight=210&originWidth=1802&originalType=binary&ratio=1&rotation=0&showTitle=false&size=99709&status=done&style=none&taskId=ua23ac429-4f57-4469-b419-194099299c5&title=&width=901)
客户端的报文：
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666602927642-1eca63df-742b-418b-a2ab-8379271d704d.png#clientId=ub3bce9d4-8e4c-4&from=paste&height=205&id=u366cff82&name=image.png&originHeight=410&originWidth=2872&originalType=binary&ratio=1&rotation=0&showTitle=false&size=570921&status=done&style=none&taskId=u2f5a8f26-718b-4409-899a-12ef56120c4&title=&width=1436)
#### mytracer跟踪
在server端部署mytracer进行函数抓取，同时两端抓包可以看出来最后一个fin实际出现3次0.3秒的情况了，但是curl记录的是0.6秒，说明curl的时间线是传输结束（发送finack），不是记录的整个四次挥手的过程

默认的stack：
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666603030059-aa4e4858-7f84-447d-a64b-8e5fa4292319.png#clientId=ub3bce9d4-8e4c-4&from=paste&height=666&id=udce637a9&name=image.png&originHeight=1332&originWidth=1821&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1165338&status=done&style=none&taskId=u2a3e2330-b62a-478e-9fbe-a915559df7a&title=&width=910.5)
mytracer跟踪的函数延迟，对比内核路径图不难发现，tc的延迟作用在      ip_finish_output2+0x209的下一跳  __dev_queue_xmit+0x1 上，而tcpdump的抓包点在更下面的dev_hard_start_xmit（对照开篇的内核路径图），因此tcpdump看到的是延迟后的报文
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666602822022-b610347c-9255-461a-8ed0-6d8b8f8a7bb5.png#clientId=ub3bce9d4-8e4c-4&from=paste&height=452&id=uaf532613&name=image.png&originHeight=904&originWidth=1668&originalType=binary&ratio=1&rotation=0&showTitle=false&size=319475&status=done&style=none&taskId=uefd5b750-6f7e-41d1-afd7-91ae0795d60&title=&width=834)
有些同学可能会遇到看到的是dev_queue_xmit函数，不带__,实际上dev_queue_xmit封装的是__dev_queue_xmit
```
int dev_queue_xmit(struct sk_buff *skb)
{
	return __dev_queue_xmit(skb, NULL);
}
EXPORT_SYMBOL(dev_queue_xmit);
```
继续往下可以使用faddr2line把这个函数地址对应的源码找出来看下，可以看到x01对应的3787行是这个__dev_queue_xmit发送函数的开始位置
```
# bash faddr2line /usr/lib/debug/lib/modules/4.19.91-26.5.al7.x86_64/vmlinux __dev_queue_xmit+0x1
__dev_queue_xmit+0x1/0x910:
__dev_queue_xmit at net/core/dev.c:3787

#cat -n  /usr/src/debug/kernel-4.19.91-26.5.al7/linux-4.19.91-26.5.al7.x86_64/net/core/dev.c
 
  3786  static int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
  3787  {
  3788          struct net_device *dev = skb->dev;
  3789          struct netdev_queue *txq;
  3790          struct Qdisc *q;
  3791          int rc = -ENOMEM;
  3792          bool again = false;
  3793
  3794          skb_reset_mac_header(skb);
  3795
  3796          if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
  3797                  __skb_tstamp_tx(skb, NULL, skb->sk, SCM_TSTAMP_SCHED);
  3798
  3799          /* Disable soft irqs for various locks below. Also
  3800           * stops preemption for RCU.
  3801           */
  3802          rcu_read_lock_bh();
  3803
  3804          skb_update_prio(skb);
  3805
  3806          qdisc_pkt_len_init(skb);
  3807  #ifdef CONFIG_NET_CLS_ACT
  3808          skb->tc_at_ingress = 0;
  3809  # ifdef CONFIG_NET_EGRESS
  3810          if (static_branch_unlikely(&egress_needed_key)) {
  3811                  skb = sch_handle_egress(skb, &rc, dev);
  3812                  if (!skb)
  3813                          goto out;
  3814          }
  3815  # endif
  3816  #endif
  3817          /* If device/qdisc don't need skb->dst, release it right now while
  3818           * its hot in this cpu cache.
  3819           */
  3820          if (dev->priv_flags & IFF_XMIT_DST_RELEASE)
  3821                  skb_dst_drop(skb);
  3822          else
  3823                  skb_dst_force(skb);
  3824
          /*此处主要是取出此netdevice的txq和txq的Qdisc,Qdisc主要用于进行拥塞处理，一般的情况下，直接将 
         *数据包发送给driver了，如果遇到Busy的状况，就需要进行拥塞处理了，就会用到Qdisc*/  
  3825          txq = netdev_pick_tx(dev, skb, sb_dev);
  3826          q = rcu_dereference_bh(txq->qdisc);
  3827
  3828          trace_net_dev_queue(skb);
   /*如果Qdisc有对应的enqueue规则，就会调用__dev_xmit_skb，进入带有拥塞的控制的Flow，注意这个地方，虽然是走拥塞控制的 
     *Flow但是并不一定非得进行enqueue操作啦，只有Busy的状况下，才会走Qdisc的enqueue/dequeue操作进行 
     */  
  3829          if (q->enqueue) {
  3830                  rc = __dev_xmit_skb(skb, q, dev, txq);
  3831                  goto out;
  3832          }
```


tc在报文发送的流程中的位置，这里直接借用 [@九善(wangrui.ruiwang)](/wangrui.ruiwang) 同学的一个图示
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666840046786-72aefeb8-1da5-4eba-97b8-b77d62c68136.png#clientId=u2ac78acf-e5f7-4&from=paste&height=643&id=ua8d9daaa&name=image.png&originHeight=1286&originWidth=2556&originalType=binary&ratio=1&rotation=0&showTitle=false&size=1309341&status=done&style=none&taskId=u06179d84-0d7e-46cc-bbae-029d1de20b2&title=&width=1278)

**分析小结：**
使用mytracer做延迟分析，需要对内核的协议栈稍微有所了解，我们对这种问题可以不用个个都去看内核函数调用路径信息，tc跟实际的业务延迟有所不同，在业务慢的场景，如tcp queue堆积，应用一直没有去调用rcv收数据，我们大概率会看到延迟的调用栈会包含 tcp_data_queue这种函数，使用mytracer分析只需要看看延迟出现的上下文大概分析即可，结合抓包分析效果更佳。


### 更高版本的一个神器pwru：
pwru 是 cilium 推出的基于 eBPF 开发的网络数据包排查工具，它提供了更细粒度的网络数据包排查方案，但是对内核版本要求较高，不做测试了
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666252497073-17fd4f8f-9fee-4cf3-8f85-a5fae7417b96.png#clientId=u70b47896-d039-4&errorMessage=unknown%20error&from=paste&height=475&id=u8fcdc1ff&name=image.png&originHeight=950&originWidth=1678&originalType=binary&ratio=1&rotation=0&showTitle=false&size=913760&status=error&style=none&taskId=ua918a758-1c24-4863-812e-6817e62cec7&title=&width=839)
## ####update 2022-10-20###
为了便于分析某些延迟类型的问题，将默认的time模块更换成datetime，支持毫秒级展示，效果如下：
![image.png](https://intranetproxy.alipay.com/skylark/lark/0/2022/png/26092/1666256443836-0bea1ec0-4ffb-4782-b465-8d2ca686164e.png#clientId=u70b47896-d039-4&errorMessage=unknown%20error&from=paste&height=297&id=ubd93bde4&name=image.png&originHeight=594&originWidth=2448&originalType=binary&ratio=1&rotation=0&showTitle=false&size=270033&status=error&style=none&taskId=u81b4c70c-580a-4f30-83c1-68ac5016e46&title=&width=1224)
