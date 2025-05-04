# ALP Bomber

`ALP Bomber` 是一款使用 Rust 编写的高性能 UDP 压力测试工具。

---

## 🛠️ 构建

需要 Rust 环境：

```bash
git clone https://your-repo-url.git
cd alp-bomber
cargo build --release
```

编译完成后，二进制文件在 `target/release/alp-bomber`。

---

## 📦 使用方法

```bash
./alp-bomber <IP> [PORT] [--threads <N>] [--size <BYTES>] [--rate <PPS>] [--duration <SECONDS>]
```

| 参数               | 类型  | 默认值 | 描述                                                     |
| ------------------ | ----- | ------ | -------------------------------------------------------- |
| `<IP>`             | 必选  | 无     | 目标 IP 地址或主机名                                     |
| `[PORT]`           | u16   | `0`    | 目标端口                                                 |
| `-t`, `--threads`  | usize | `64`   | 工作线程数量                                             |
| `-s`, `--size`     | usize | `0`    | 数据包大小，0 表示在 64\~1024 字节间随机                 |
| `-r`, `--rate`     | u64   | `0`    | 每秒发送包数上限（0 表示无限制）                         |
| `-d`, `--duration` | u64   | `100`  | 攻击持续时间，单位秒；0 表示无限制，需手动停止（Ctrl+C） |

---

### 🔧 示例

- 向 192.168.1.10 发起 60 秒的默认攻击

```bash
./alp-bomber 192.168.1.10
```

- 使用 128 个线程，固定端口 9000，每包 512 字节

```bash
./alp-bomber 192.168.1.10 --port 9000 -t 128 -s 512
```

- 控制速率为 5000 PPS，持续 30 秒

```bash
./alp-bomber 192.168.1.10 --rate 5000 --duration 30
```

- 压测域名（自动解析 IP）

```bash
./alp-bomber example.com -s 1024
```

## ⚠️ 法律声明

本项目仅供合法压力测试用途。禁止将本工具用于任何未经授权的攻击行为，开发者不对任何滥用行为承担责任。
