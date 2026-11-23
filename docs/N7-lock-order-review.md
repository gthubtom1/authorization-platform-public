# N7 锁序复核（2026-09-26，本机只读复核，未改代码）

## 复核目标

本复核独立核对历史提出的「回收路径 ABBA、物理封禁 ABBA」两条锁序声称，回答两个问题；原评分流水已清理，以下证据与结论自包含：

1. N7 描述的两条 ABBA 在当前树上**是否还存在**？
2. 是否构成**必须改代码**的死锁风险？

## 锁序图（每条路径按 `select_for_update` 实际拿锁顺序列出）

### 路径 A · 批量回收外层 `licensing/api_views.py::_lock_reclaim_resources`

```
with transaction.atomic():
    lock LicenseCard           (sorted by public_id)
    lock DownstreamProfile     (sorted by public_id)
    lock QuotaAccount          (sorted by downstream_public_id)
```

代码注释明确写：

```
The order must match the per-card service path in
``credits.services.reclaim_license_card`` (LicenseCard → DownstreamProfile
→ QuotaAccount).  Locking profiles/accounts before the cards here used to
be the exact reverse, so a batch reclaim and a single-card reclaim running
at the same time could deadlock on the same two rows.
```

**这是过去已经修好的项**——N7 描述的「外层 Profile → QuotaAccount → LicenseCard」在当前树**不存在**。

### 路径 B · 回收内层 `credits/services.py::_refund_license_card_quota`

```
with transaction.atomic():
    lock LicenseCard           (by public_id)
    lock DownstreamProfile     (by public_id)
    lock QuotaAccount          (by downstream_public_id)
```

与路径 A 顺序完全一致。

**结论：路径 A、B 同向。原 N7 回收 ABBA 已被前人修好，当前复核未发现存在。**

### 路径 C · 物理封禁 `licensing/admin.py::block_physical_device`

```
with transaction.atomic():
    pass 1: SELECT DeviceBinding WHERE device=? AND state=ACTIVE   (no lock)
    pass 2: lock LicenseInstance  (for each authorization_id, sorted, one by one)
    pass 3: lock Device           (by pk)
    pass 4: lock DeviceBinding    (for the device, ACTIVE, ordered by binding_id)
    with retry if active_bindings set is inconsistent (inner_rollback + retry)
```

### 路径 D · 授权内核 verify `licensing/authorization.py::_verify_device_proof` 调用链

参考审查报告的核对，授权 verify 的实际拿锁顺序是：

```
LicenseCard → LicenseInstance → Device → DeviceKey → DeviceBinding
```

## N7 声称「物理封禁 ABBA」的实际形态

报告写"block_physical: Device → DeviceBinding → LicenseInstance"，但**当前树实际是**：

```
LicenseInstance → Device → DeviceBinding
```

与 verify (D) 比较：

| 顺序位 | verify (D)             | block_physical (C)      |
|---|---|---|
| 1 | LicenseCard        | LicenseInstance      |
| 2 | LicenseInstance    | Device               |
| 3 | Device             | DeviceBinding        |
| 4 | DeviceKey          |                        |
| 5 | DeviceBinding      |                        |

C 与 D 在 LicenseInstance、Device、DeviceBinding 上**同向**（I→D→B），只是 C 不拿 LicenseCard/DeviceKey。

**潜在风险点：**C 在 pass 1 先用「无锁 SELECT」枚举 DeviceBinding，再回来锁 LicenseInstance。这意味着**并发**下「枚举绑定集合」与「锁定之后的实际绑定集合」可能不一致。但代码做了 retry 循环（`_PHYSICAL_DEVICE_LOCK_RETRIES`），发现 missing 就 `transaction.set_rollback(True)` 重来。这是**乐观锁+重试**，不是死锁 ABBA。

verify (D) 是「先锁 LicenseCard」，block (C) 不锁 LicenseCard。C 不写 LicenseCard，所以即使并发 verify 拿着 card 锁等 instance 锁、block 拿着 instance 锁，block 也不需要拿 card 锁，**不会形成等待环**。

## 复核结论

1. **回收路径 N7 ABBA 已不存在**——`_lock_reclaim_resources` 与 `_refund_license_card_quota` 已统一为 LicenseCard → DownstreamProfile → QuotaAccount。审查报告描述的「外层 Profile → QuotaAccount → LicenseCard」**在当前树上不存在**，是过时报备。
2. **物理封禁 ABBA 在当前树不构成 ABBA**——`block_physical_device` 实际锁序是 LicenseInstance → Device → DeviceBinding，与 verify 的 LicenseCard → LicenseInstance → Device → DeviceKey → DeviceBinding 同向（共享部分是 I→D→B）；且 block 不拿 LicenseCard，verify 先拿 card 再拿 instance，二者在 card 上无相互等待，**不会形成等待环**。
3. **C 的乐观重试机制**（pass 1 无锁枚举、pass 4 锁中发现 missing 就 set_rollback 重试）防止"枚举后看到旧绑定集合"这种竞态演化为死锁，代价是可能 retry 数次。
4. **因此本轮不改代码。** 审查报告 N7 的两条锁序声称在当前树**不成立**，没有实证死锁需要修。

## 仍然要 PG 实测的项

以下不因静态复核就排除，仍需要真实 PG 多线程才能定性；但这是「**进一步保险**」，不是「修已有 bug」：

- C 的 retry 循环在真高并发下是否会退化为 N 次重试才能成功？（性能问题，不是死锁问题）
- C pass 1 无锁 SELECT 的并发语义在 PG 默认隔离级别（READ COMMITTED）下是否真的能保证 retry 后拿到完整集合？

这两项未来若要做实测，可以用 `scripts/postgresql-concurrency-acceptance.ps1` 的隔离环境写一组发包×封禁配对线程用例，跑 N=100 看 retry 计数分布。**建议：不阻塞当前 P1 列表、不写代码；如果一定要做，把它列成一个新的低优先级实测任务。**

## 本次复核未做的事

- 没改 `licensing/` 或 `credits/` 任何产品代码
- 没动数据库、没起 PG、没改 STATUS 里其他 P1 项目
- 没承诺死锁绝对不存在（只是审查报告的两条具体声称在当前树不成立）
