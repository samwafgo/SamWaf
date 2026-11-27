#!/bin/sh
# 开发时生成两种字节序的内嵌对象；运行 SamWAF 不需要 clang、libbpf 或外部加载命令。
set -eu
cd "$(dirname "$0")"
task_bpf_multiarch=$(gcc -dumpmachine)
for target in bpfel bpfeb; do
    # Debian/Ubuntu 的 asm UAPI 头位于多架构目录；Alpine 仍使用普通 /usr/include。
    clang -O2 -g -fdebug-prefix-map="$(pwd)"=. -I"/usr/include/$task_bpf_multiarch" -target "$target" -Wall -Werror -c input.c -o "input_$target.o"
done
