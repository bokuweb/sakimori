# Sakimori — eBPF-based Audit & Block for GitHub Actions

aya-rs を使い、GitHub Actions 実行環境で network / file アクセスを監査・ブロックする
Rust 製ツール。`StepSecurity/harden-runner` に相当する機能を eBPF で実装する。

## ゴール

- GitHub Actions の job / step 中で発生する以下のイベントを観測する
  - **Network**: `connect(2)` による外向き通信 (IPv4 / IPv6, TCP/UDP)
  - **File**: `openat(2)` による read / write アクセス
  - **Process**: `execve(2)` による子プロセス起動
- ポリシーに違反したイベントを **audit** (記録のみ) または **block** (失敗させる) する
- 監査ログを JSON でファイル / stdout に出力し、Actions summary に要約を添付する

## 非ゴール (初期版)

- Windows / macOS サポート (eBPF は Linux のみ)
- LSM BPF による完全な MAC (初期は `sys_enter` tracepoint + `bpf_override_return` + cgroup/skb で代替)
- コンテナ外からのネストされた監査

## 技術選定

- **aya** — pure-Rust eBPF toolkit。外部依存 (clang, libbpf) なしでビルド可
- **aya-ebpf** — kernel 側プログラム用 crate (`no_std`, target `bpfel-unknown-none`)
- **aya-log** — eBPF → userspace のログ
- **tokio** — userspace 側の非同期ランタイム
- **clap** — CLI
- **serde / serde_json** — ポリシー & ログ
- **anyhow / thiserror** — エラー処理

ターゲット: Linux x86_64 / aarch64, kernel 5.13+ (cgroup/skb, ringbuf)。

## ワークスペース構成

```
sakimori/
├── Cargo.toml                # workspace
├── PLAN.md
├── crates/
│   ├── sakimori/           # userspace CLI: `sakimori run -- <cmd>`
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs
│   │       ├── policy.rs     # YAML/JSON policy loader
│   │       ├── loader.rs     # aya で .o を load, map を配る
│   │       ├── events.rs     # ringbuf → 構造化ログ
│   │       ├── enforcer.rs   # allow/deny 判定, map 更新
│   │       └── report.rs     # JSON ログ + GH summary
│   ├── sakimori-ebpf/      # kernel 側
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── net.rs        # cgroup/connect4, connect6
│   │       ├── file.rs       # tracepoint sys_enter_openat
│   │       └── exec.rs       # tracepoint sys_enter_execve
│   └── sakimori-common/    # userspace / ebpf 共有の POD 構造体
│       ├── Cargo.toml
│       └── src/lib.rs
├── action.yml                # GitHub Actions composite action
└── rust-toolchain.toml       # nightly + rust-src (aya-ebpf 用)
```

## ポリシーフォーマット

```yaml
# .github/sakimori.yml
mode: block   # audit | block
network:
  default: deny
  allow:
    - host: api.github.com
      ports: [443]
    - cidr: 140.82.112.0/20
      ports: [22, 443]
file:
  default: allow
  deny:
    - /etc/shadow
    - /home/*/.ssh/**
  write_only_deny:
    - /usr/**
process:
  deny_exec:
    - /usr/bin/curl   # 代わりに明示許可した HTTP client だけ使え、など
```

- host 名は userspace 側で事前 resolve して IP map に展開
- glob は userspace で展開、kernel 側は prefix/suffix マッチ

## eBPF プログラム設計

### network (egress)
- **cgroup/connect4, cgroup/connect6** attach
- 現在 cgroup を `/sys/fs/cgroup/sakimori.slice/<uuid>` に作成し、対象プロセスを enroll
- map: `HashMap<IpKey, AllowEntry>` (IPv4 / IPv6 別), `Array<Mode>` (audit/block)
- block 時は `return 0` (userspace から見ると EPERM) / audit 時は ringbuf に push して allow
- 追加で `cgroup_skb/egress` で DNS 問い合わせ先もキャプチャ (stretch)

### file
- **tracepoint:syscalls:sys_enter_openat** で filename を読む (`bpf_probe_read_user_str`)
- deny list は `HashMap<FilePrefixKey, DenyEntry>` (最大 256 bytes, LPM は stretch)
- block 時は `bpf_send_signal(SIGKILL)` もしくは `bpf_override_return(-EPERM)` (要 `CONFIG_BPF_KPROBE_OVERRIDE`)
- 初期は kprobe + override_return で `do_sys_openat2` を対象にする案を検討

### exec
- **tracepoint:syscalls:sys_enter_execve** で argv[0] / filename を ringbuf へ
- deny list は HashMap 参照。block は kprobe override で `-EPERM`

### 共有 ringbuf
- `RingBuf` (size 256KiB) を 1 本。event は `enum Event { Net, File, Exec }` をタグ付けし userspace で `bytemuck` で decode。

## userspace フロー

1. CLI 起動 → policy 読み込み → `cgroup` を作成
2. `aya::Ebpf::load` で ELF を読み込み、プログラムを `attach`
3. policy を map に書き込む (IP 集合、file prefix 集合, mode)
4. `fork()` → 子プロセスを作り自身を cgroup に入れて `exec` (ユーザ指定コマンド)
5. 親プロセスは ringbuf を poll し、event を JSON でログ
6. 子プロセス終了コードを親の exit code とする。block 違反があり `mode=block` の場合は非 0 で終了
7. 終了時に JSON summary を `$GITHUB_STEP_SUMMARY` に append

## GitHub Actions 統合

`action.yml` で composite action を提供:

```yaml
inputs:
  policy:
    description: Path to policy file
    default: .github/sakimori.yml
  mode:
    description: audit | block
    default: audit
runs:
  using: composite
  steps:
    - run: curl -sSfL https://github.com/bokuweb/sakimori/releases/download/${{ env.SAKIMORI_VERSION }}/sakimori-x86_64-unknown-linux-musl.tar.gz | tar xz -C /usr/local/bin
      shell: bash
    - run: sudo sakimori daemon --policy ${{ inputs.policy }} --mode ${{ inputs.mode }} &
      shell: bash
```

…ただし GitHub-hosted runner は sudo が使える ubuntu-latest のみ対応。

## 開発ステップ

| Step | 内容 | 成果物 |
|------|-----|--------|
| 1 | workspace + 共有 crate の雛形 | Cargo workspace がビルドできる |
| 2 | ebpf crate の雛形 (空の tracepoint) + aya loader | `sakimori run -- /bin/true` が動く |
| 3 | exec tracepoint + ringbuf 出力 | execve イベントが JSON で出る |
| 4 | cgroup/connect4 + IPv4 allow/deny | network block の e2e |
| 5 | connect6 追加 / DNS 解決 | host 名ポリシー対応 |
| 6 | file open tracepoint + prefix match | file audit |
| 7 | block モード (override_return) | file block |
| 8 | policy loader (YAML) + summary | 実用レベル |
| 9 | action.yml + CI でクロスコンパイル | リリース |

## 現状の実装方針 (このセッション)

本環境は macOS の為、実行確認はできないが **コンパイルが通るところまで** 実装する。

- [x] PLAN.md 作成
- [x] Cargo workspace 化
- [x] `sakimori-common` crate (イベント構造体 + マップキー)
- [x] `sakimori-ebpf` crate (execve / openat / connect4 / connect6)
- [x] `sakimori` (userspace) crate (CLI + aya loader)
- [x] cgroup v2 作成 & 子プロセス `pre_exec` enroll
- [x] ringbuf ドレイン tokio タスク
- [x] hostname / IP / CIDR を Resolver で展開し NET4/NET6 に投入
- [x] `action.yml` composite action + CI workflow
- [x] `rust-toolchain.toml` / `.cargo/config.toml`

### 残タスク (Linux 実機検証が必要)

- [ ] eBPF ELF のビルド検証 (`cargo +nightly build --target bpfel-unknown-none`)
- [ ] GitHub-hosted ubuntu-latest での e2e (audit → block)
- [ ] file path prefix マップ (kernel 側 deny) の実装
- [ ] `bpf_override_return` による execve/openat deny
- [ ] リリース (`cargo-dist` などで musl static build + bpf.o 同梱)

## リスク / 未解決

- **nightly 依存**: `aya-ebpf` は nightly + `rust-src` 必須。CI で pin する
- **override_return**: kernel config 依存。audit モードを既定値にする
- **GitHub-hosted runner の権限**: `CAP_BPF`, `CAP_SYS_ADMIN` が必要。`ubuntu-latest` (sudo) ではOKだが、container job では別途検討
- **IPv6 / dual-stack**: `connect6` に `::ffff:a.b.c.d` で来る場合があるので両方ケアする
- **パフォーマンス**: ringbuf は lock-free だが burst で溢れると loss する。`lost_samples` を report に含める
