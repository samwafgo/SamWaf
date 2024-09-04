# SamWaf 行为准则

## 轻量化
   SamWaf主分支启动时候，不依赖任何三方服务，为的是给使用的用户一个清爽的环境。
   我们在维护主分支必定不要新增其他依赖服务如mysql,redis等等。
## 隐私保护
   SamWaf力争所有通讯数据进行加密处理，并保存在本地，不上远端。
## 提交规范
- feat: 新功能（feature）
- fix: 修补bug
- docs: 文档（documentation）
- style: 格式（不影响代码运行的变动）
- refactor: 重构（即不是新增功能，也不是修改bug的代码变动）
- chore: 构建过程或辅助工具的变动
- revert: 撤销，版本回退
- perf: 性能优化
- test:测试
- improvement: 改进
- build: 打包
- ci: 持续集成