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

## 发布时间证明（timeproof）

`channel.propose/publish` 里的 `at` 是请求方自报值，只能驱动既有窗口检查，不能在争议中作为独立 UTC 证明。`imagecourt/timeproof.py` 在保留旧的 `source/stamp/certificate`（取最小 `claimed_utc` 的 `provisional` 证书）行为的同时，增加了基于区间与原件的镜像晋级时间证明：

- 每份严格时钟原件（`op:"witness"`）含运营主体、签署链、校准时段、偏差区间和全局不可重用的 `witness_seq`；重用序号返回 `witness_seq_reused`。同一 `operator` 或同一 `upstream_group`（共用上游失准源）的见证归为同一个独立根，不能冒充两份独立见证。
- 自报时刻 `c` 与偏差 `[omin,omax]` 形成绝对区间 `[c+omin,c+omax]`，多源取交集（另给保守包络 `interval_envelope`）；相对偏差再加共用上游的绝对误差区间。绝不取最小 `claimed_utc` 当作确定时刻。
- `events.seq` 只证明本地提交先后。`order_certificate` 是限缩证书：只证明申请序号先于发布序号，`certified_utc` 为空，明确 `production_window_met=null`、`window_claim=not_evaluated`。
- `release_certificate` 出具带绝对区间的正式证书，对半开窗口 `[start,expires)` 给出三态结论：`provably_within` / `provably_outside` / `insufficient_evidence`（证书状态分别为 `time_certified` / `time_certified_outside` / `time_unproven`）。证据不足时不倒填时刻。
- 时钟倒拨在 stamp 上标记并写入 `clock_anomalies`；`backfill/offline` 离线补报单独留存且不算倒拨。`calibrate` 只追加校准版本，报告同时给出 `known_then_interval`（当时可知）与 `current_interval`（迟到校准后修订）。已出具证书行不可改写，只能用 `correct_certificate` 追加更正；原证书按锁定的 `clock_version` 仍可复算验证。
- 证书锁定镜像摘要、发布代次、申请/发布 `events` 原文摘要（`sha256(events.payload)`）、合并 `events_digest` 与固定校准版本的 `clock_version`；`verify_certificate` 可发现摘要、代次、窗口或时钟版本被转贴/篡改。`disclosure_package` 分别给出客户限缩包与保密审阅原件包。

生产镜像 D 的跨时钟失准原件在 `fixtures/release_time_cross_clock.json`：自报第 29 分钟、第 30 分钟关窗；节点钟 ±3 → `[26,32]`、签署设备 ±2 → `[27,31]`，交集 `[27,31]` 跨越 30，结论为 `time_unproven`，而序号 18<21 仍证明申请先于发布。独立审阅者可不建库直接复算：

```sh
python -m imagecourt.timeproof fixtures/release_time_cross_clock.json
python -B -m unittest tests.test_release_time_proof -v
python -B -m unittest discover -s tests -q
```

