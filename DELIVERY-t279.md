# 交付文档：HPKE export-only 模式补齐（t279-circl）

## 1. 背景与根因

端到端加密归档网关用 HPKE 做信道密钥派生，归档侧只需要密钥调度与导出接口
（`Context.Export`）派生对称密钥。按 RFC 9180 §5.3/§7.3，这类应用应选择
**export-only 的 AEAD 代码点 `0xFFFF`** 构造套件。

接入测试发现该代码点在套件构造入口直接崩溃，export-only 模式完全不可用。根因链条：

| 位置 | 加固前行为 | 根因 |
|---|---|---|
| `AEAD.IsValid()`（`hpke/algs.go`） | 只认 `0x01/0x02/0x03`，`0xFFFF` 返回 false | 代码点未进入注册表 |
| `NewSuite()`（`hpke/hpke.go`） | `!s.isValid()` 成立 → `panic(ErrInvalidHPKESuite)` | **题面所述"套件构造入口直接崩溃"** |
| `AEAD.New/KeySize/NonceSize/CipherLen` | `0xFFFF` 落 default 分支 `panic(ErrInvalidAEAD)` | 无该代码点的语义 |
| `state.keySchedule()`（`hpke/util.go`） | 无条件推导 `key` 与 `base_nonce` 并 `aeadID.New(key)` | 未按 §5.3 跳过加密密钥派生 |
| `unmarshalContext()`（`hpke/marshal.go`） | 无条件 `aeadID.New(c.key)` | 空 key 无法实例化 AEAD |
| `sealContext.Seal` / `openContext.Open`（`hpke/aead.go`） | 直接解引用 `c.AEAD` | 空 AEAD → nil 解引用崩溃 |

`hpke/hpke.go` 包注释中原本挂着一条 `BUG(cjpatton)` 明确写着"不实现 Export-Only
模式、不识别 0xFFFF 代码点"，即该缺口在仓里是有据可查的已知未实现项。

向量侧：`hpke/vectors_test.go` 的 `vector.verify` 对 `!aead.IsValid()` 的条目
`t.Skipf`。由于 `0xFFFF` 被判为非法，仓里自带的 RFC 9180 官方向量
（`hpke/testdata/vectors_rfc9180_5f503c5.json.gz`）中 **32 条 export-only 条目
全部被静默跳过**（基线实测 `SKIP: TestVectors/v*` 计数 = 32），官方一致性验收
"躺在仓里跑不起来"。

## 2. 模式语义与空字段取舍（设计决定及理由）

以下决定均以 RFC 9180 的规范文本为依据。

### 2.1 export-only 上下文跳过 key 与 base_nonce 派生

RFC 9180 §5.3 原文说明：只用 Export 接口的应用"可以选择 export-only 的 AEAD
ID `0xFFFF`"，并且"可以避免在密钥调度中计算 `key` 与 `base_nonce`，因为 Export
接口不使用它们"。因此：

- `keySchedule` 在 `aeadID == AEAD_ExportOnly` 时，只用规范规定的
  `secret = LabeledExtract(...)` 与 `exporter_secret = LabeledExpand(secret, "exp", ...)`
  两条路径，**不调用** `KeySize`/`NonceSize`/`New`，也不推导 key/base_nonce。
- 导出密钥派生路径保持规范语义：`Export()` 仍是
  `LabeledExpand(exporter_secret, "sec", exporter_context, L)`，与 RFC 9180 §5.3
  的定义逐字对应，因此 24 组（4 KEM × 2 KDF × ... 见 §5）官方向量的导出值全部
  逐字节命中。

**取舍：跳过 vs 仍推导再丢弃。** 选择跳过，理由是：§5.3 的许可就是为省去这份
无用的密钥材料而设；更重要的是 `Nk`/`Nn` 在 §7.3 登记为 `N/A`，规范根本没有给
export-only 定义密钥长度和 nonce 长度，若强行给一个长度（例如借用 16/12）去推导，
就等于凭空发明一套不在规范内的派生输入，会让导出密钥之外的字节产生不可对照的
偏移量，反而破坏"与规范一致"。跳过是唯一有规范依据的做法。

### 2.2 空字段：序列化为零长度向量的空 key / base_nonce / seq

export-only 上下文没有 key、没有 base nonce、没有序列号。序列化格式
（`hpke/marshal.go` 自定义的 `HpkeContext`，非规范格式）对这三个字段用
`opaque <0..255>` 编码。选择**写为零长度向量（长度字节 `0x00` + 0 字节内容）**，
而不是省略字段或写 `nil`：

- **格式可读且自描述**：三个字段各占一个 `0x00` 长度字节，解析侧按
  `ReadUint8LengthPrefixed` 读到空切片，字段边界清晰，人能直接对照结构图读出来；
  若省略字段则解析器无法区分"字段缺失"与"空字段"，破坏格式的自描述性。
- **往返保持**：`unmarshalContext` 把空的 key/nonce/seq 读回空切片，并按 suite
  判断是 export-only，于是不再实例化 AEAD，`Export` 在往返后产物与原来逐字节一致
  （`TestExportOnlySerialization` 覆盖 sealer 与 opener 两侧）。
- **既有格式逐字节不变**：常规 AEAD 套件的 marshalling 分支完全未触碰，`key` 与
  `base_nonce` 仍分别是 `Nk`/`Nn` 字节，字段顺序与长度前缀都不变（见 §6 基线比对）。

### 2.3 加密原语调用显式报错，不崩溃也不静默成功

export-only 上下文实现 `Sealer`/`Opener` 接口（因为它必须能作为 `Context`
返回给调用者，`Setup` 的返回类型即如此），但对加密原语调用一律返回新增的
导出错误 `ErrAEADExportOnly`：

- **不崩溃**：`Seal`/`Open` 先判 suite，命中 export-only 直接返回错误，绝不
  解引用空的 `c.AEAD`。
- **不静默成功**：不复用"空 key + 全零 nonce 去 Seal"之类的伪实现。那种做法
  输出的是无意义的密文却返回 nil 错误，调用方（尤其是并存的灰度实例）会把噪声
  当成合法归档数据，这是本次最需杜绝的静默失败形态。
- `AEAD.New(0xFFFF)` 同样返回 `ErrAEADExportOnly`，把"这个代码点没有 AEAD"
  的语义统一到算法注册表层，调用方无需了解内部 suite 结构即可判别。

**为什么返回 `Sealer`/`Opener` 而不是新增只含 `Context` 的返回值：** 改动
`Setup` 的返回类型会是破坏性 API 变更，题干要求"既有真实 AEAD 套件的行为与
序列化格式逐字节不变"以及改动面收在 hpke 包内的最小化原则；保持返回类型不变、
在加密原语层显式报错，是既满足"export-only 上下文的加密原语调用显式报错"又不
动摇既有调用方签名的做法。

### 2.4 新导出标识符与错误

- `AEAD_ExportOnly AEAD = 0xFFFF`：公开常量，与既有 `AEAD_AES128GCM` 等命名
  风格一致，带 godoc 说明 §5.3/§7.3 依据。
- `ErrAEADExportOnly`：公开错误值，供调用方用 `errors.Is`/相等比较判别。
- `AEAD.KeySize()/NonceSize()/CipherLen()` 对 `0xFFFF` 返回 `0`，对应 §7.3
  的 `N/A`，而非 panic——这样即使有外部代码查询这些属性也不会崩溃。

## 3. 题面要求逐条落地对照

| # | 题面要求 | 落地改动 |
|---|---|---|
| 1 | 该代码点的套件构造不再崩溃 | `algs.go` `IsValid` 纳入 `0xFFFF`；`NewSuite` 经 `isValid` 通过，不再 panic |
| 2 | export-only 上下文跳过加密密钥与随机数派生 | `util.go` `keySchedule` 新增 `AEAD_ExportOnly` 分支，只推 `secret` 与 `exporter_secret` |
| 3 | 导出密钥派生路径保持规范语义 | `aead.go` `Export` 未改动，仍为 `LabeledExpand(exporterSecret, "sec", ctx, L)` |
| 4 | 收发两侧导出结果逐字节一致 | 同一 `keySchedule` 供 sender/receiver 使用；`TestExportOnlyExportConsistency` 逐上下文断言相等 |
| 5 | 加密原语调用显式报错而非崩溃/静默成功 | `aead.go` `Seal`/`Open` 前置判 suite 返回 `ErrAEADExportOnly`；`algs.go` `New` 同样返回该错误 |
| 6 | 上下文序列化对空密钥与空随机数字段往返可读 | `util.go` 置空 key/baseNonce/seq；`marshal.go` 判 suite 不实例化 AEAD；`TestExportOnlySerialization` + `checkExportOnlyEncoding` |
| 7 | 官方向量中 export-only 条目全部启用不再静默跳过 | `algs.go` 使 `IsValid` 为真，`vectors_test.go` 的 `t.Skipf` 自然不再触发；新增 `TestExportOnlyOfficialVectors` 显式回放 |
| 8 | 既有真实 AEAD 套件行为与序列化格式逐字节不变 | 常规分支代码未改；§6 基线 worktree 逐字节比对 IDENTICAL |
| 9 | 实现细节与导出接口文档注释一致 | `hpke.go` 包注释、`Sealer.Seal`/`Opener.Open` 注释、`marshal.go` 格式注释、`algs.go` 常量与各方法 godoc 同步更新 |
| 10 | 模式语义与空字段取舍写明理由 | 本文档 §2 |
| 11 | 改动面逐文件登记 | 本文档 §4 |
| 12 | 构造读数与验收命令最终读数并排 | 本文档 §5 |
| 13 | 新增三类断言用例落位 hpke_test.go，框架与既有用例一致 | `hpke/hpke_test.go`（`package hpke_test`，纯 `testing`），见 §4 与 §5 |
| 14 | 改动面收在 hpke 包内，既有测试保持通过 | 仅改 `hpke/` 下 6 个文件；`go test ./hpke/... ./kem/...` 全通过 |

## 4. 改动面逐文件登记

| 文件 | 类型 | 改动内容 |
|---|---|---|
| `hpke/algs.go` | 生产代码 | 新增常量 `AEAD_ExportOnly = 0xFFFF`；`New` 对其返回 `ErrAEADExportOnly`；`IsValid` 纳入该代码点；`KeySize`/`NonceSize`/`CipherLen` 对其返回 `0`。均为新增 switch 分支，既有三个真实 AEAD 分支逐字未改。 |
| `hpke/util.go` | 生产代码 | `keySchedule` 新增 `AEAD_ExportOnly` 提前返回分支：只推导 `secret` 与 `exporter_secret`，返回空 key/baseNonce/sequenceNumber 且不带 AEAD 的上下文。常规分支的推导语句与顺序**逐字未改**（`exporter` 仍在 `base_nonce` 之后推导）。 |
| `hpke/aead.go` | 生产代码 | `sealContext.Seal` 与 `openContext.Open` 在调用 `c.AEAD` 前判 suite，export-only 直接返回 `ErrAEADExportOnly`。常规路径逐字未改。`Export` 与 `calcNonce`/`increment` 未改动。 |
| `hpke/marshal.go` | 生产代码 | `unmarshalContext` 在 export-only 时跳过 `aeadID.New` 实例化（suite 已被校验）；`MarshalBinary` 文档补 export-only 空字段说明。序列化写侧代码未改。 |
| `hpke/hpke.go` | 生产代码 | 移除 `BUG(cjpatton)` 注释，替换为 export-only 模式说明；`Sealer.Seal`/`Opener.Open` 接口注释补 `ErrAEADExportOnly`；新增错误值 `ErrAEADExportOnly`。 |
| `hpke/hpke_test.go` | 测试（唯一测试改动文件） | 新增 6 个测试与辅助：`TestExportOnlyAEADProperties`（代码点属性）、`TestExportOnlySuiteConstruction`（构造不崩溃，4 组算法）、`TestExportOnlyExportConsistency`（收/发导出逐字节一致）、`TestExportOnlyEncryptionRejected`（Seal/Open 显式报错且不 panic）、`TestExportOnlySerialization`（空字段序列化往返可读 + 导出保持 + 角色校验）、`TestExportOnlyOfficialVectors`（32 条 export-only 官方向量逐条回放并输出逐字节读数）；辅助结构 `officialExportVector`/`exportKAT`、`checkExportOnlyEncoding`、`checkNoPanic`、`readOfficialExportVectors`。复用 `internal/test` 的 `ReadGzip` 与 `test.HexBytes`，与 `vectors_test.go` 同一数据源。 |

`hpke/vectors_test.go` **未做任何修改**：其 `t.Skipf` 条件之所以不再触发，是因为
`0xFFFF` 现在被 `IsValid` 认可，这是生产代码修复的自然结果，无需改动测试去
"取消跳过"——这也正好证明修复是从根因上生效的。

未新增/修改任何导出 API（除新增的 `AEAD_ExportOnly` 常量与 `ErrAEADExportOnly`
错误值，均为纯增量）；未触及 `kem` 包与仓库其它包。

## 5. 构造读数与验收命令最终读数（并排）

### 5.1 构造输入与读数口径

**固定构造输入**：仓库自带 `hpke/testdata/vectors_rfc9180_5f503c5.json.gz` 中
`aead_id = 0xFFFF` 的 **32 条 export-only 条目**。每条使用向量自带的模式
（`mode` 0–3 全覆盖）、算法组合（KEM `0x10/0x12/0x20/0x21` × KDF
`0x01/0x03`）与向量自带输入密钥材料（`ikmR`/`skRm`/`pkRm`、`ikmE`、
auth 模式的 `skSm`/`pkSm`、PSK 模式的 `psk`/`psk_id`、`info`），以确定性
encapsulation 种子复现，逐条取 `Export(exporter_context, L)` 的**逐字节十六进制
读数**。快照环境内零外部依赖（数据来自仓内 testdata，无网络、无第三方服务）。

读数由 `go test -count=1 -run TestExportOnlyOfficialVectors ./hpke/ -v` 输出
（每行格式 `mode=… kem=… kdf=… aead=ffff ctx=… L=32 export=…`），共
**32 条 × 每条 3 个 exporter_context（空 / `0x00` / `TestContext`）= 96 行**，
且每条读数与向量自带的 `exported_value` 逐字节相等（不相等则测试失败）。

### 5.2 构造读数（节选，完整 96 行见测试输出）

代表性四组（KEM `0x20`、KDF `0x01`，mode 0→3，`ctx=` 空）：

| mode | 构造结果 |
|---|---|
| 0 | `7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36` |
| 1 | `be6c76955334376aa23e936be013ba8bbae90ae74ed995c1c6157e6f08dd5316` |
| 2 | `83c1bac00a45ed4cb6bd8a6007d2ce4ec501f55e485c5642bd01bf6b6d7d6f0a` |
| 3 | `dafd8beb94c5802535c22ff4c1af8946c98df2c417e187c6ccafe45335810b58` |

mode 0、KEM `0x20`、KDF `0x01` 的三个上下文读数（与向量 `exported_value` 逐字节一致）：

| exporter_context | export 读数 |
|---|---|
| 空 | `7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36` |
| `00` | `d5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0` |
| `54657374436f6e74657874`（`TestContext`） | `ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e` |

其余 88 行读数同一命令完整输出，全部命中向量期望值。

### 5.3 验收命令最终读数

命令：

```bash
go test -count=1 ./hpke/... ./kem/...
```

最终读数（exit code 0，零失败）：

```
ok  	github.com/cloudflare/circl/hpke	1.211s
ok  	github.com/cloudflare/circl/kem/frodo	2.208s
ok  	github.com/cloudflare/circl/kem/hybrid	0.617s
ok  	github.com/cloudflare/circl/kem/kyber	0.658s
ok  	github.com/cloudflare/circl/kem/mlkem	0.759s
ok  	github.com/cloudflare/circl/kem/schemes	0.929s
ok  	github.com/cloudflare/circl/kem/xwing	0.459s
```

无 `FAIL`、无 `SKIP`。`go test -count=1 ./hpke/ -v` 的跳过计数为 **0**
（基线为 32，全部来自被静默跳过的 export-only 向量）。`gofmt -l hpke/` 为空，
`go vet ./hpke/...` 干净。

## 6. 既有 AEAD 套件行为与序列化格式逐字节不变的验证

在临时 git worktree 检出**未改动的 HEAD**（`059a2b1`）作为基线，两棵树使用
同一读数程序，以固定 `DeriveKeyPair` 种子 + 固定 encapsulation 种子驱动
4 组真实 AEAD 套件（`P256+SHA256+AES128GCM`、`P384+SHA384+AES256GCM`、
`X25519+SHA256+ChaCha20Poly1305`、`X25519-Kyber768+SHA256+AES128GCM`），
打印并比对以下字段：

- 密钥调度：`key`、`base_nonce`、`exporter_secret`、`secret`、`key_schedule_context`、`shared_secret`
- 加密输出：`Seal("plaintext","aad")` 的密文
- 导出：`Export(nil,32)` 与 `Export("TestContext",32)`
- 序列化：`MarshalBinary()` 的 sealer 与 opener 全部字节
- 算法属性：`KeySize`/`NonceSize`/`CipherLen`、`getSuiteID`、`String()`

结果：`diff -q` → **IDENTICAL**。即常规 AEAD 套件的密钥调度、密文、导出值、
序列化格式全部逐字节不变。

## 7. 回读重放的兼容性说明（审计侧上下文标签与长度档）

题面提到审计侧按登记的上下文标签与长度档回读重放导出派生，且回读条目中**存在
登记为空上下文标签的档位**。本改动对此的处理：

- 空上下文标签（`exporter_context` 为空/`nil`，及长度档如 32）在 export-only
  路径下正常工作：`Export(nil, L)` 与 `Export([]{}, L)` 均按
  `LabeledExpand(exporter_secret, "sec", nil, L)` 求值，与规范一致，且收发两侧
  逐字节相等。`TestExportOnlyExportConsistency` 显式覆盖 `nil` 上下文与
  `archive/stream/42`、`{0x00}` 等标签，并断言不同标签产出不同读数。
- 「空上下文标签」与「空标签数组」是同一语义（`nil` 与 `[]byte{}` 在
  `LabeledExpand` 中 `len(info)==0`，编码一致），因此回读重放不会因登记形态是
  `null` 还是空字符串而产生密钥材料分歧——`TestExportOnlyExportConsistency`
  的记录里保留 `nil` 上下文即覆盖此档。
- 滚动升级并存期：新旧两代实例对同一归档流按同一套件与同一上下文登记重放，
  由于导出密钥派生路径与规范逐字一致、且与向量自带的 `exported_value` 逐字节
  命中，新旧实例（常规套件对照组 vs export-only 灰度实例）在**相同输入下**的
  导出读数可直接比对作为放量闸门；两者属于不同 suite（`aead_id` 不同，进而
  `suite_id` 不同），读数本就应当不同，灰度闸门应比对的是同代内收发一致性与
  对向量的命中，而非跨代绝对值相等。

## 8. 复现方式

```bash
# 构造读数（96 行，逐条 export-only 条目 × 3 上下文）
go test -count=1 -run TestExportOnlyOfficialVectors ./hpke/ -v

# 三类断言用例
go test -count=1 -run 'TestExportOnly' ./hpke/ -v

# 官方向量全量（export-only 条目不再 SKIP）
go test -count=1 -run TestVectors ./hpke/ -v

# 验收命令
go test -count=1 ./hpke/... ./kem/...
```
