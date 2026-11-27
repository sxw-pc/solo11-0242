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

## 客户数据清除与最小司法留置

`imagecourt/retention.py` 在登记 `artifact_copies`、`preservation_orders`、`erase_requests` 的基础上，补齐了可执行的删除闭环；`tests/test_erasure_hold.py` 与 `fixtures/erasure_hold_multisite.json` 给出两站点、缓存、仍生效旧租约工作负载、备份与其他租户同摘要副本的合成场景。

- **定位精度**：按租户 + 镜像摘要 + 数据类别（`artifact_segments` 的字节区间）+ 实际副本/站点（`copy_ids`/`sites`）定位；同摘要下其他租户的合法副本原样保留。
- **最小留置令**：`court_order`/`legal_hold` 必须给出签署方 `signer`、时间 `at|issued_at`、争议事项 `matter` 与锁定的最小字节范围 `ranges`（或 `segments`/`range_categories` 引用），否则返回 `invalid_order`。
- **实物清除**：`fulfill`/`purge` 逐字覆写每个站点副本、`artifact_caches` 与 `runtime_artifacts`（即使 `leases` 仍 `active`），并 `destroy_backups`；不是只藏索引。
- **两条合法路径**：`mode=isolated_custody` 把最小片段封入与生产隔离的 `custody_items`/`custody_keys`（保管人、密钥引用、用途、`custody_access` 取用记录），证明明确保留范围；`mode=external_escrow` 把片段交付独立司法托管（可写 `escrow_dir` 外部文件汇槽），平台只留哈希承诺并签发 `zero_retention_external_escrow` 零留存证明。
- **四类事实与证明闸口**：`erasure_facts` 分别记录 `physical`、`backup`、`judicial`、`receipt`；任一失败（如 `faults` 注入的部分清除失败、`escrow_unreachable`）只得到 `incomplete` 证明与 `blockers`，不会提前签发完整 `erasure_certificates`。
- **可重放删除证明**：原始 `copy` 事件写入的 payload 会在确认清除后按目标被涂销（redaction，保留 `payload_hash` 承诺并写 `event_redactions`），清除事件自身只携带覆写残差/证据；`store.replay` 重放业务裁决、逐表比对状态并校验事件哈希链与涂销承诺，被清除的原始 payload 不会在日志或重放库中重生。撤销留置（`revoke_hold`）只能销毁当时实际封存的最小片段与密钥，且不能从旧事件恢复已删字节；重复客户请求按 id / `idempotency_key` 返回 `reused`。

```sh
python -B -m unittest tests.test_erasure_hold -v
python -B -m unittest discover -s tests -q
```
