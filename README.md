Fat-Tree 路由图：

![image-20220112231442877](README.assets/image-20220112231442877.png)

路由设计代码 `LPR.py, LSR.py, LLR.py` 以及流量生成代码 `parallel_traffic_generator.py, sequential_traffic_generator.py` 在 `RyuRoute` 目录下。

 `LPR.py, LSR.py, LLR.py` 三者结构基本相同，区别主要在 `get_port` 函数（该函数根据当前节点以及目的 IP 地址查找下一个节点的端口号）

### LPR

靠左选择

用两个进程运行命令：

```bash
ryu-manager LPR.py --observe-links > LPR_out.txt
sudo python3 parallel_traffic_generator.py
```

将在 `LPR_out.txt` 中得到 h3->h7 和 h3->h8 的首包路径

格式为 `ethertype src_ip -> dst_ip : dpid in_port out_port`

> 运行结束后，需手动中止前一个进程

### RSR

随机选择

类似地，用两个进程运行命令：

```bash
ryu-manager RSR.py --observe-links > RSR_out.txt
sudo python3 parallel_traffic_generator.py
```

将在 `RSR_out.txt` 中得到 h3->h7 和 h3->h8 的首包路径

### LLR

最低负载选择

用两个进程运行命令：

```bash
ryu-manager LLR.py --observe-links > LLR_out.txt
sudo python3 sequential_traffic_generator.py
```

将在 `LLR_out.txt` 中得到前 10 条首包路径
