# psy-bridge-sp1

`psy-bridge-sp1` 是 `psy-doge-solana-bridge` 当前真实 block-transition 证明路径使用的 **SP1 v6.3.1** workspace。

唯一运行时证明 guest 是 `block-transition`：它验证序列化的 Dogecoin bridge state 与 block witness，使用 manager custody script config、确认数和 deposit fee 参数执行 block transition，并把验证后的状态与旧/新 Solana `PsyBridgeHeader` 的共识字段绑定。对应的 `gen-proof` host 使用 `ProverClient::builder().cpu()`，生成 Groth16 proof 后立即通过 SP1 SDK `client.verify(...)` 自验证；它不是网络服务，也不监听端口。

Withdrawal 不使用 ZK：bridge 在链上原子授权输出并发出 Wormhole VAA，Manager 达到 5-of-7 quorum 后签名并广播 Dogecoin 交易，确认后由任何人提交 finalize。

> 该 workspace 证明 block witness 对给定旧状态的转换，以及该结果与提交到 Solana 的 header/config/custodian commitment 一致。它不自行运行 Dogecoin 节点、Solana validator 或 Wormhole Guardian。

> 新增或修改 guest、生成 program VK、接入 non-mock Solana verifier 的完整流程见 [`DEVELOPING_CIRCUITS.md`](./DEVELOPING_CIRCUITS.md)。

## Workspace 结构

```text
lib/                                      共享 SHA-256/public-input 公式
program/src/bin/block_transition.rs       mandatory block-update proof guest
program/src/bin/manual_claim.rs           retained manual-claim guest（无本仓库 runtime host）
program/src/bin/custodian_transition.rs   retained custodian-transition guest（无本仓库 runtime host）
script/src/bin/gen_proof.rs               block-transition CPU prover CLI
script/build.rs                           用 sp1-build 编译 program package guest ELF
```

版本由 Cargo manifests 固定：

- `sp1-zkvm = "6.3.1"`
- `sp1-sdk = "6.3.1"`
- `sp1-build = "6.3.1"`

这不是 SP1 v5 workspace。若 guest、SP1 crate、proof ABI 或 Solana verifier key 任一发生变化，必须重建 proof，并同步更新/部署 verifier；不能复用旧 proof 或旧 ELF。

## 前置条件

1. **Rust nightly**：根目录 `rust-toolchain` 指定 `channel = "nightly"`，并安装 `llvm-tools`、`rustc-dev`。
2. **Edition 2024 能力**：虽然本 workspace package edition 是 2021，SP1 v6 依赖图中的 crate 需要能解析/构建 Edition 2024。过旧 stable/nightly 会在依赖解析或编译阶段失败；使用当前 `rust-toolchain` 所选的新 nightly。
3. **Succinct/SP1 toolchain**：`sp1-build` 构建 guest 时会调用 Succinct toolchain。正常构建日志会显示类似 `rustc +succinct --version`。
4. **`protoc`**：SP1 依赖的 protobuf build scripts 需要 Protocol Buffers compiler。确认：

   ```bash
   protoc --version
   ```

   Ubuntu/Debian 通常安装：

   ```bash
   sudo apt-get install protobuf-compiler
   ```

5. **本机资源**：当前 CLI 强制使用 CPU prover。Groth16 proving 是高 CPU/内存、明显长于普通 Rust build 的作业；不要用短的通用命令 timeout 判断失败。首次运行还会编译 guest/host 依赖。

快速检查：

```bash
cd ~/Projects/psy-bridge-sp1
rustc --version
cargo --version
protoc --version
cargo build --release -p psy-bridge-sp1-script --bin gen-proof
```

`script/build.rs` 在 host build 期间调用：

```rust
sp1_build::build_program_with_args("../program", Default::default());
```

生成并嵌入的 guest ELF 是 `block-transition`。host binary 位于：

```text
target/release/gen-proof
```

## Block-transition guest

### 精确 stdin 布局

Guest 依次调用十次 `sp1_zkvm::io::read_vec()`；因此这是 **十个 SP1 framed vector**，不能拼成一个无 framing 的 blob：

| 顺序 | CLI option                   | 解码后长度 | 含义 |
| ---: | ---------------------------- | ---------: | ---- |
|    1 | `--old-state`                | 可变       | Borsh 编码的旧 Dogecoin bridge state。 |
|    2 | `--witness`                  | 可变       | Speedy 编码的 block-transition witness。 |
|    3 | `--custody-script-config`    |   32 bytes | Manager custody script config preimage，即 emitter bridge PDA。 |
|    4 | `--required-confirmations`   |    4 bytes | CLI `u32`，host 以 little-endian 写入。 |
|    5 | `--flat-fee`                 |    8 bytes | Deposit flat fee，host 以 little-endian 写入。 |
|    6 | `--fee-num`                  |    8 bytes | Deposit fee numerator，host 以 little-endian 写入。 |
|    7 | `--fee-den`                  |    8 bytes | Deposit fee denominator，host 以 little-endian 写入。 |
|    8 | `--old-header`               |  320 bytes | 旧 Solana `PsyBridgeHeader` canonical `#[repr(C)]` bytes。 |
|    9 | `--new-header`               |  320 bytes | 新 Solana `PsyBridgeHeader` canonical `#[repr(C)]` bytes。 |
|   10 | `--config-params`            |   48 bytes | Bridge config canonical `#[repr(C)]` bytes。 |

Host 对 custody script config、两个 header 和 config 做精确长度检查；state/witness 由 guest 中的 Borsh/Speedy parser 完整消费。所有 byte options 接受内联 hex、`0x` 前缀、`@path/to/file` 或直接存在的文件路径；文件内容仍须是 hex 文本，解析会去掉 ASCII whitespace。

### Guest 验证与 public value

Guest 先解析旧 state 和 witness，并通过 `prover_guest_verify_block_transition_detailed::<DogeRegTestConfig>` 检查 block/witness transition。随后它检查旧/新 Solana header 的 finalized block hash、Merkle root、auto-claim roots/index 和 block height与验证结果一致。Solana-only pending-mint/TXO-buffer hashes由链上 buffer checks 验证，不在 guest 中重复检查。

最后 guest 与 host 使用同一 public-value 公式：

```text
old_header_hash = SHA256(old_header[320])
new_header_hash = SHA256(new_header[320])
config_hash     = SHA256(config_params[48])
custodian_hash  = CustodyScriptConfig(custody_script_config[32]).hash()
transition_hash = SHA256(old_header_hash || new_header_hash)
public_value    = SHA256(transition_hash || config_hash || custodian_hash)
```

提交值为 32 bytes。Host 独立计算同一公式，要求 `proof.public_values` 完全相等，然后才写文件。

### 实际 CLI

完整 proof invocation：

```bash
cargo run --release -p psy-bridge-sp1-script --bin gen-proof -- \
  --old-state <hex-or-@file> \
  --witness <hex-or-@file> \
  --custody-script-config <32-byte-hex-or-@file> \
  --required-confirmations <u32> \
  --flat-fee <u64> \
  --fee-num <u64> \
  --fee-den <u64> \
  --old-header <320-byte-hex-or-@file> \
  --new-header <320-byte-hex-or-@file> \
  --config-params <48-byte-hex-or-@file>
```

只需从当前 release ELF 导出 program VK 时，可运行：

```bash
cargo run --release -p psy-bridge-sp1-script --bin gen-proof -- --vkey-only
```

该模式输出 `block_elf_path` 与 `vkey_hash`，不生成 proof artifact。

### 固定输出

此 CLI 当前没有 `--output-dir`；每次成功都会覆盖：

| 文件                                       |  期望长度 | 内容                                        |
| ------------------------------------------ | --------: | ------------------------------------------- |
| `/tmp/bridge-block-transition-proof.bin`   | 356 bytes | SP1 v6 Groth16 verifier input/proof bytes。 |
| `/tmp/bridge-block-transition-pubvals.bin` |  32 bytes | 上述 `public_value`。                       |

stdout 还输出 `proof_path`、`proof_size`、完整 proof hex、public-values path/size/hex 和 `vkey_hash`。

当前 release guest 的 `--vkey-only` 输出：

```text
vkey_hash: 0x00a46ec348b525eea327ac89a090b17c44dab7e399a1d9fa4668c52cba1ba672
```

Solana `doge-bridge` 的 non-mock `SINGLE_BLOCK_UPDATE_VK` 必须与该值逐字节相同；`BLOCK_REORG_VK` 当前别名到相同 key。Guest source、linked guest dependencies、SP1 toolchain 或 build configuration 变化后必须重新导出并核对，不能复用旧样本。

## Withdrawal lifecycle

Withdrawal proof guest、host binary、public-input ABI 和 verification key 已删除。Withdrawal 的授权语义由 Solana instruction 直接验证：请求 membership 与输出严格 1:1/order、最多一个 canonical change output；随后通过 Wormhole VAA 和 5-of-7 Manager signatures 授权 Dogecoin broadcast，并在确认后用 discriminator 17 permissionlessly finalize。

因此 withdrawal 不产生 SP1 proof/public-values artifact，也没有 withdrawal VK 或 prover runtime dependency。

## 356-byte proof ABI

当前 Solana verifier 接受的 proof 是 **356 bytes**，不是只取 Groth16 body 的 256 bytes：

```text
4-byte Groth16 circuit-VK hash prefix
+ 96-byte SP1 v6 metadata
+ 256-byte Groth16 proof body
= 356 bytes
```

因此：

- 不要沿用旧 256-byte 假设；
- 不要删除前 100 bytes；
- 不要把其他 workspace 的 SP1 v5/v6 proof 或 VK 与本 workspace 混用；
- proof length 正确仍不足以证明兼容，VK hash、guest ELF 与 public values 也必须匹配。

## SDK verification 与链上验证

`gen-proof` 执行以下顺序：

1. `client.setup(ELF)` 生成 proving/verifying key；
2. `client.prove(...).groth16().await`；
3. 从 proof 取出 public values，并与 host 独立公式比较；
4. `client.verify(&proof, verifying_key, None)`；
5. 验证成功后才写输出。

这建立了 SP1 SDK 层的本机验证。链上兼容性还需要 non-`mock-zkp` 的 `psy-doge-solana-bridge` 使用 block-transition key 验证完整 356-byte proof。Withdrawal lifecycle 不进入 SP1 verifier。

## CPU proof 预期

- prover 被硬编码为 `.cpu()`；当前没有 CLI flag 切换网络 prover/GPU。
- 首次运行包含大量依赖和 guest ELF build，后续缓存命中后 host 启动更快，但 Groth16 proving 本身仍是重 CPU 作业。
- CPU 时间依赖硬件、系统负载和缓存，不应把某台机器的秒数写成保证值。
- 自动化应给 proof job 独立长 timeout，并同时监控进程退出状态和输出文件长度。
- 对 block CLI，应在运行前删除/隔离固定 `/tmp` 旧文件，因为成功会覆盖固定路径；E2E 测试已经在启动 prover 前删除 stale outputs。

## 与桥集成

当前 real E2E 从 bridge/CLI block pipeline 调用：

```bash
cargo run --release -p psy-bridge-sp1-script --bin gen-proof -- ...
```

桥侧 VK 定义位于：

```text
psy-doge-solana-bridge/programs/doge-bridge/src/processor.rs
```

必须使用 non-mock build。标准 Makefile/大量 legacy tests 默认启用 `mock-zkp`；这些测试能覆盖状态机和 buffer 流程，但不能证明本 README 所述 proof 被密码学验证。

## 故障排查

### `edition2024` / manifest parse / compiler too old

原因通常是实际执行的 Cargo/Rust 没有使用本目录 `rust-toolchain` 指向的新 nightly。进入 workspace 根目录重试，并确认 `rustc --version`、`cargo --version`。不要通过降级 SP1 crate 来掩盖工具链不匹配。

### 找不到 `protoc`

安装 Protocol Buffers compiler，确认 `protoc --version` 后重新 build。仅安装 Rust protobuf crate 不会提供系统 `protoc` binary。

### `rustc +succinct` 或 guest build 失败

确认 SP1/Succinct toolchain 已安装且可由 `sp1-build` 调用。删除/覆盖 host binary 不能修复缺失的 guest toolchain。

### 输入错误

`custody-script-config / old-header / new-header / config-params` 分别必须解码为 `32 / 320 / 320 / 48` bytes。`old-state` 与 `witness` 是可变长度编码，但必须能被 guest 的 Borsh/Speedy parser 完整解析；所有文件参数必须包含 hex 文本。

### proof 是 256 bytes 或链上报 proof format 错误

这是旧 ABI/截断 proof。当前完整输出必须是 356 bytes。重新使用 SP1 v6.3.1 CLI 生成，不要手工抽取 Groth16 body。

### VK mismatch / 链上 verification failed

按顺序核对：

1. CLI stdout 的 `vkey_hash`；
2. `processor.rs` 的 `SINGLE_BLOCK_UPDATE_VK`；
3. validator 实际部署的 `doge_bridge.so` 是否是刚构建的 non-mock ELF；
4. proof 与 public values 是否来自同一次、同一输入运行；
5. 是否错误复用了 SP1 v5、scrypt guest 或其他 workspace 的 proof。

切换 feature/VK 后必须重建并重启 validator/重新部署。`target` 中存在新文件不代表链上 program 已更新。

### `ComputationalBudgetExceeded`

这是链上交易 compute budget，不是 SP1 SDK 自验证失败。提交 real Groth16 verification 时增加 Solana compute-unit limit；不要为通过测试而改用 `mock-zkp`。

### 输出看似成功但文件是旧的

`gen-proof` 使用固定 `/tmp` 路径。运行前删除旧 proof/public-values，运行后要求进程 exit 0、文件 mtime 更新、长度分别为 `356/32`。

## 安全范围

- 代码和本地 E2E 未经生产审计，不应直接用于真实资产。
- block guest 在 zkVM 内执行 helper 的 block/witness transition verification，并把验证结果锚定到 Solana header 的共识字段；pending-mint/TXO-buffer commitments 仍依赖链上 buffer checks。
- 当前 guest 使用 `DogeRegTestConfig`，因此这个 release ELF/VK 仅适用于相同网络规则的 regtest pipeline；支持其他 Dogecoin network 必须使用相应 config 重建 guest、VK、proof 与 bridge deployment。
- Withdrawal 的安全性来自链上 authorize 约束、Wormhole VAA、Manager quorum、Dogecoin confirmation 和 permissionless finalize，而非 ZK。

跨仓库完整流程与 E2E 证据由 `solana-doge-ibc/integration/e2e/` 维护；生产操作命令位于 `psy-doge-solana-cli/doge/`。
