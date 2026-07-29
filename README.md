<h1>Smart Proxy IP Checker</h1>

定时检测 Cloudflare 代理 IP 的可用性，筛选低欺诈分的纯净 IP，并自动推送到指定 API。

## 工作流程

GitHub Action 每小时第 5 分钟自动执行（`cron: 5 */1 * * *`），也可手动触发。

+ **步骤 1** — 从 `zip.cm.edu.kg/all.txt` 拉取完整 IP 库，按国家筛选
+ **步骤 2** — 从 Cloudflare IP 性能 CSV 中读取各国家最优 IP
+ **步骤 3** — 合并两者构建预选池（每国采样 50 个，选出 10 个）
+ **步骤 4** — 通过 TCP + TLS + SNI 直连探测每个 IP 的可用性
+ **步骤 5** — 生成结果文件并 commit 到仓库
+ **步骤 6** — 解析 `pureip.txt` 中所有纯净 IP，推送到配置的 API

## 输出文件

| 文件 | 说明 |
|------|------|
| `pureip.txt` | 欺诈分低于阈值的纯净 IP，格式 `ip#国家|速度|TCP延迟|TLS延迟|IPPure:分数` |
| `proxyip.txt` | 每国前 N 个有效 IP（含性能备注） |
| `prefecthip.txt` | 所有通过检测的有效 IP |
| `ip-all.txt` | 完整 IP 库缓存 |

## 配置 Secrets

在仓库 **Settings > Secrets and variables > Actions** 中添加：

| Secret | 说明 | 示例 |
|--------|------|------|
| `PUSH_API_URL` | 推送目标地址 | `https://kxzn.svi.cc.cd` |
| `PUSH_API_TOKEN` | Bearer 认证 token | `your-bearer-token` |
| `CHECK_PASSWORD` | 检测接口密码（可选） | `your-password` |

## 推送 API 格式

```
POST {PUSH_API_URL}/api/proxy-ips
Authorization: Bearer {PUSH_API_TOKEN}
Content-Type: application/json
```

请求体示例：

```json
[
  {
    "ip": "1.2.3.4",
    "country": "香港",
    "provider": "Cloudflare",
    "latency": 10,
    "speed": 125.5
  }
]
```

> `country` 自动将国家代码（US、HK、JP 等）映射为中文名称。未匹配的代码保持原样。

## 环境变量

在 workflow 文件的 `env` 区块可调整以下参数：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `COUNTRY_LIMIT` | `US,DE,GB,JP,SG,HK,KR,TW,NL` | 目标国家列表（逗号分隔） |
| `SAMPLE_PER_COUNTRY` | `50` | 每国采样数 |
| `IPS_PER_COUNTRY` | `10` | 每国最终输出到 proxyip.txt 的数量 |
| `FRAUD_THRESHOLD` | `30` | 纯净 IP 欺诈分上限（低于此值进入 pureip.txt） |
| `BATCH_SIZE` | `20` | 每批检测 IP 数量 |
| `REQUEST_TIMEOUT` | `60` | 单次探测超时（秒） |

## 手动运行

进入仓库 **Actions** 页面，选择 **Smart Proxy IP Checker**，点击 **Run workflow**。

## 本地调试

```bash
# 直接探测指定 IP
python direct_check.py 104.26.0.1:443 --json

# 从文件批量探测
python direct_check.py -f ips.txt --json

# 启动探针服务（需部署到 Cloudflare 代理域名后方）
python probe_server.py --port 8443
```

## 项目文件

| 文件 | 说明 |
|------|------|
| `check-proxyip.yml` | GitHub Actions 工作流（放于 `.github/workflows/`） |
| `direct_check.py` | TCP+TLS+SNI 直连探测引擎 |
| `push_ips.py` | 解析 `pureip.txt` 并推送到 API |
| `probe_server.py` | Cloudflare 探针源站服务 |
| `deploy/` | 探针服务部署文件（systemd） |
