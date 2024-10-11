# ip 库的处理

## 机制
1. SamWaf为了轻量化内置了ip2region.xdb。
2. 遇到识别不准的问题就得自己构建放在 data/ip2region.xdb,重启SamWaf就可以了。

## 如何生成 ip2region.xdb
这里使用 Ip2region(狮子的魂)。为了方便测试使用，fork了一份，生成了windows和linux的可执行文件。

https://github.com/samwafgo/ip2region/releases



- 1.编辑

```
xdb_maker.exe edit --src=./ip.merge.txt

```

打开ip.merge.txt ，我们拿8.8.8.8来测试。把这个复制出来：8.8.8.0|8.8.8.255|美国|0|0|0|Level3 ，稍加改动

```

put 8.8.8.0|8.8.8.255|美国测试|0|0|0|Level3

```

- 2.保存

```
save
```


退出xdb_maker

```

quit 

```

- 3.最后生成db文件

```
xdb_maker.exe gen --src=./ip.merge.txt --dst=./ip2region.xdb
```

这个时候会花几分钟时候构建，出现这个就OK了，可以复制ip2region.xdb到data下了

```

2024/10/10 16:17:08 maker.go:283: try to write the vector index block ...
2024/10/10 16:17:08 maker.go:294: try to write the segment index ptr ...
2024/10/10 16:17:08 maker.go:307: write done, dataBlocks: 13828, indexBlocks: (683843, 720464), indexPtr: (983612, 11070094)
2024/10/10 16:17:08 main.go:112: Done, elapsed: 2m36.219498s

```

- 4.【可选】 批量测试是否正常：
  会挺慢几分钟
```

xdb_maker.exe bench --db=./ip2region.xdb --src=./ip.merge.txt

```


``` 
|-try to bench ip '224.0.0.0' ...  --[Ok]
|-try to bench ip '247.255.255.255' ...  --[Ok]
|-try to bench ip '239.255.255.255' ...  --[Ok]
|-try to bench ip '247.255.255.255' ...  --[Ok]
|-try to bench ip '255.255.255.255' ...  --[Ok]
Bench finished, {count: 3419215, failed: 0, took: 3m48.3903262s}
```

 
## 查询相关

- 1.替换后 通过日志查看
 

![SamWaf Architecture](/docs/common_images/ipchange.png)

- 2.测试数据库查询是否正常，也可以用工具先看看：

xdb_searcher.exe search --db=./ip2region.xdb

```

iptest>xdb_searcher.exe search --db=./ip2region.xdb
ip2region xdb searcher test program, cachePolicy: vectorIndex
type 'quit' to exit
ip2region>> 8.8.8.8
[0;32m{region: 美国测试|0|0|0|Level3, ioCount: 7, took: 617.7µs}[0m
ip2region>> quit
searcher test program exited, thanks for trying

```