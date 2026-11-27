# 镜像来源准入与发布庭

离线的容器镜像来源、环境晋级和运行准入业务模拟器。只使用 Python 标准库与 SQLite，不连接真实镜像仓库或集群，不保存真实密钥。

三个入口分别维护来源证据（清单、构建证明、组件清单和风险事实）、环境通道（晋级申请、限期例外和指针历史）、运行准入（工作负载、租约、孤儿副本与隔离）。来源撤销会使通道和租约转风险；通道撤回须先清理依赖实例。请求和结果记入 `events`，可逐条重放并逐表核对。

在仓库根目录运行：

```sh
python -m imagecourt demo --db demo.sqlite
python -m imagecourt replay --db demo.sqlite
python -m unittest discover -s tests -v
```

各入口可分别运行 `python -m imagecourt provenance|channel|admission|energy --db state.sqlite --fixture fixtures/<入口>_normal.json`；同名 `_failure.json` 为失败样例。`channel` 需要先执行来源样例，`admission` 需要先执行通道样例。使用新数据库运行演示以避免旧状态影响身份冲突的结论。

## 构建用电与绿色权益（energy 扩展）

电表读数与可宣称的绿色电力是两份独立的权益，分别建账：

- **物理用电账（独占注销）**：`meter_devices` 记录设备编号、站点、地域与校准有效期；`meter_readings` 按连续覆盖时窗登记读数，携带代次（revision）与可信低碳证据。`energy_runs`/`build_segments` 把构建拆成开始、暂停、重试与共享设备待机逐段对账；`build_finish` 把每段物理用电登记到 `energy_allocations`，同一读数被各批次分走的总量永远不超过可信读数，跨站点、跨账期（时窗不重叠）的借用直接拒绝。
- **绿色属性账（证书链）**：`green_certificates` 保存证书序列、发电站、发电时段、地域、初始所有者；`certificate_transfers` 是逐手转让链，`cert_retire` 只能由当前所有者按同地域、同时段把属性永久注销到某一构建（`certificate_retirements`）。注销后证书余量归零，不能再卖给第二个批次。
- **两种声明口径分别出具**：`claim_green` 的 `grid_source` 口径只承认电表可核证的物理低碳份额（`physical_kwh`，须有证据且不超读数），不得夹带证书；`market` 口径可用已注销证书补足剩余 kwh，但物理与证书之和不得超过构建实测用电，杜绝同一份电重复计绿。
- **不可覆盖、只能追加**：声明在 `green_claim_versions` 中按版本留痕，`claim_publish` 后不可改写，更正只能 `claim_new_version`；电表更正（`meter_correct`）、校准撤销（`meter_decertify`）、转让撤销（`cert_revoke_transfer`）与构建重跑（`build_rerun`）只在 `claim_impacts` 追加受影响声明与补救责任，证书注销回执和已发表声明保持原样。镜像摘要不变不代表构建地点、用电时段与属性权利不变，重跑会产生新的 run 并标记旧声明受影响。

绿色样例：`fixtures/green_shared_meter.json`（共享电表与连续读数）、`fixtures/green_single_certificate.json`（单张证书及转让链）、`fixtures/green_failure.json`（拒绝样例）；对应验收测试为 `tests/test_build_green_rights.py`。旧的 `meter`/`build`/`claim` 事件与 `electricity_readings`、`build_energy_runs`、`green_claims` 表保持原契约不变，历史事件仍可逐条重放。
