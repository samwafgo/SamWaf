#!/bin/sh
# 开发时生成两种字节序的内嵌对象；运行 SamWAF 不需要 clang、libbpf 或外部加载命令。
set -eu
cd "$(dirname "$0")"
for target in bpfel bpfeb; do
    clang -O2 -g -fdebug-prefix-map="$(pwd)"=. -target "$target" -Wall -Werror -c input.c -o "input_$target.o"
done
