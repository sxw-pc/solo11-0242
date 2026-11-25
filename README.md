# 镜像来源准入与发布庭

离线的容器镜像来源、环境晋级和运行准入业务模拟器。只使用 Python 标准库与 SQLite，不连接真实镜像仓库或集群，不保存真实密钥。

三个入口分别维护来源证据（清单、构建证明、组件清单和风险事实）、环境通道（晋级申请、限期例外和指针历史）、运行准入（工作负载、租约、孤儿副本与隔离）。来源撤销会使通道和租约转风险；通道撤回须先清理依赖实例。请求和结果记入 `events`，可逐条重放并逐表核对。

在仓库根目录运行：

```sh
python -m imagecourt demo --db demo.sqlite
python -m imagecourt replay --db demo.sqlite
python -m unittest discover -s tests -v
```

各入口可分别运行 `python -m imagecourt provenance|channel|admission --db state.sqlite --fixture fixtures/<入口>_normal.json`；同名 `_failure.json` 为失败样例。`channel` 需要先执行来源样例，`admission` 需要先执行通道样例。使用新数据库运行演示以避免旧状态影响身份冲突的结论。
