# 基于机器学习的 SDN 网络 DDoS 攻击检测与缓解系统

本仓库给出一个可落地的毕设实现骨架，面向如下目标：

- 在 **Mininet + Ryu** 仿真环境采集 OpenFlow 流统计。
- 在后端进行特征工程、模型推理与告警判断。
- 在 Web 前端展示实时流量、检测结果，并支持按流拦截/一键拦截。

## 一、总体架构

```text
Mininet Host/Switch
   │ (OpenFlow stats)
   ▼
Ryu Controller App
   │ REST / Socket
   ▼
Backend Service
  ├─ Collector: 周期拉取流表统计
  ├─ Feature Engine: 19维特征构建 + 标准化
  ├─ Detector: RandomForest + threshold
  └─ Mitigator: 下发流表（drop / redirect）
   │
   ▼
Frontend Dashboard
  ├─ 实时拓扑
  ├─ 流量趋势
  ├─ 告警与日志
  └─ 拦截操作（单条 / 一键）
```

## 二、部署建议（与你当前思路一致）

- 虚拟机：`mininet-ubuntu20.04.1`，运行 `ryu-manager 4.30` + Mininet 拓扑。
- 本地主机（Win11）：运行 Web 前后端。
- 通信方式：
  - 首选 Ryu northbound REST API（简洁、易调试）。
  - 若追求更低时延，可考虑 socket/消息队列。

## 三、与任务书的对应关系

1. **系统架构设计**：见“总体架构”。
2. **数据采集与特征工程**：由 Ryu 拉流表统计，构建训练/推理一致的 19 维特征。
3. **模型构建**：提供 `ml/train_ddos_rf.py`，使用 CIC-IDS2017 + CIC-DDoS2019 数据训练。
4. **检测与缓解联动**：后端调用 Ryu 下发拦截流表，前端可手动触发拦截。

## 四、工程实现关键点

- **训练与在线特征严格一致**：尤其 `Flow Duration` 单位必须统一为微秒。
- **阈值单独保存**：不要固定 0.5，使用验证集自动选阈值（F-beta, beta=2）。
- **误报控制策略**：
  - 先“告警观察”再“自动阻断”；
  - 结合白名单（DNS、网关、管理主机）避免误封。
- **缓解策略建议**：
  - 细粒度：按 `src_ip/dst_ip/in_port` 下发 drop；
  - 粗粒度：开启“一键拦截所有恶意流”。

## 五、答辩可展示亮点

- 拓扑仿真 + 实时可视化 + 联动缓解完整闭环。
- 跨数据集训练（CIC-IDS2017 与 CIC-DDoS2019）增强泛化。
- 阈值优化偏向高召回（攻击检测场景更实用）。

## 六、下一步建议

- 增加 `inference_service.py`：从后端实时数据构建特征并输出分类。
- 增加 `ryu_block_api.py`：封装单条/一键拦截的 southbound 调用。
- 增加离线回放脚本：复现实验曲线与指标，便于论文附录与答辩演示。

## 七、在线推理与联动缓解（新增）

### 1) 在线推理服务

`backend/inference_service.py` 提供 `DDoSInferenceService`：

- 加载训练产物（模型、标准化器、阈值元数据）。
- 对实时流统计做与训练阶段一致的特征工程。
- 输出 `score/label/confidence`，可直接喂给前端与告警模块。

最小示例：

```python
from backend.inference_service import load_service_from_artifacts

service = load_service_from_artifacts("artifacts")
results = service.predict([
    {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.100",
        "Protocol": 6,
        "Flow Duration": 500000,
        "Total Fwd Packets": 30,
        "Total Length of Fwd Packets": 9000,
        "Total Backward Packets": 2,
        "Total Length of Bwd Packets": 120,
        "Average Packet Size": 280,
    }
])
```

### 2) Ryu 拦截接口

`backend/ryu_block_api.py` 提供 `RyuBlockAPI`：

- `block_flow(...)`：按源/目的/端口精确下发 drop 规则。
- `unblock_flow(...)`：删除对应拦截规则。
- `block_all_malicious(...)`：演示用一键拦截（高风险，谨慎用于生产）。

最小示例：

```python
from backend.ryu_block_api import RyuBlockAPI

api = RyuBlockAPI(base_url="http://127.0.0.1:8080")
resp = api.block_flow(dpid=1, src_ip="10.0.0.1", dst_ip="10.0.0.100", priority=220)
print(resp.ok, resp.status_code, resp.detail)
```

## 八、现在就能跑的步骤（你当前场景）

> 下面命令默认你在项目根目录执行。Windows 建议使用 PowerShell。

### Step 0. 安装依赖

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -U pip
pip install -r requirements.txt
```

### Step 1. 训练模型（离线）

把你的数据路径替换到命令里：

```bash
python ml/train_ddos_rf.py \
  --benign-parquet "../Benign-Monday-no-metadata.parquet" \
  --train-attack-path "../train_set" \
  --test-attack-path "../test_set" \
  --attack-cache-path "../Attack_2019_ALL_FEATURES.parquet" \
  --output-dir "artifacts"
```

训练成功后会产出：

- `artifacts/ddos_final_model.pkl`
- `artifacts/final_scaler.pkl`
- `artifacts/model_meta.json`
- 三张图：混淆矩阵、ROC、特征重要性

### Step 2. 在后端里做在线推理

```python
from backend.inference_service import load_service_from_artifacts

service = load_service_from_artifacts("artifacts")

flows = [{
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.100",
    "Protocol": 6,
    "Flow Duration": 800000,  # 注意：微秒
    "Total Fwd Packets": 80,
    "Total Length of Fwd Packets": 56000,
    "Total Backward Packets": 3,
    "Total Length of Bwd Packets": 300,
    "Average Packet Size": 680,
}]

print(service.predict(flows))
```

### Step 3. 调 Ryu 拦截接口（与前端按钮联动）

先确认 Ryu 开着 `ofctl_rest`（默认 `http://127.0.0.1:8080`）：

```bash
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
```

然后在后端调用：

```python
from backend.ryu_block_api import RyuBlockAPI

api = RyuBlockAPI(base_url="http://127.0.0.1:8080")
resp = api.block_flow(dpid=1, src_ip="10.0.0.1", dst_ip="10.0.0.100", priority=220)
print(resp)
```

### Step 4. 典型联动逻辑（你的前端按钮）

- 单条拦截按钮：前端传 `src_ip/dst_ip/dpid` 给后端，后端调用 `block_flow`。
- 一键拦截按钮：后端遍历当前恶意流并逐条 `block_flow`（推荐），不要直接全局封禁。
- 解封按钮：调用 `unblock_flow`。

### 常见报错排查

- `KeyError: final_features`：`model_meta.json` 不完整，重新训练一次。
- 推理全是 `Unknown`：输入流字段没传 `src_ip/dst_ip`。
- Ryu 调用超时：检查虚拟机与主机互通、端口 `8080` 是否放行。
- 检测结果明显异常：重点确认 `Flow Duration` 单位是不是**微秒**。

## 九、把项目代码同步到你本地（Win11）

你有两种常用方式：

### 方式 A（推荐）：Git 克隆/拉取

#### 1) 第一次拉代码

```bash
git clone <你的仓库地址> SDN-DDOS-SYSTEM
cd SDN-DDOS-SYSTEM
```

#### 2) 后续同步最新代码

```bash
cd SDN-DDOS-SYSTEM
git fetch --all
git pull origin <你的分支名>
```

如果你不确定分支名，可先看：

```bash
git branch -a
```

### 方式 B：下载 ZIP（不推荐长期使用）

- 在代码托管页面点击 **Code -> Download ZIP**。
- 解压到本地目录后直接使用。
- 缺点：后续更新要重复下载，不能方便地对比/合并代码历史。

### 你这个毕设场景的推荐流程

1. 在 Win11 上 `git clone` 本仓库。
2. 在虚拟机里保留 Mininet/Ryu 运行环境。
3. Win11 后端读取 Ryu 北向接口数据并调用本仓库代码。
4. 以后每次我给你更新后，你在本地执行 `git pull` 即可同步。

### 常见问题

- `fatal: not a git repository`：你不在仓库目录里，先 `cd SDN-DDOS-SYSTEM`。
- `Authentication failed`：改用 PAT（token）或 SSH key，不要再用账号密码。
- `There is no tracking information`：首次执行

```bash
git branch --set-upstream-to=origin/<分支名> <分支名>
```

再 `git pull`。

## 十、按你的仓库链接直接同步（可复制）

你的仓库：`https://github.com/7coder-li/SDN-DDOS-SYSTEM.git`

### 第一次在 Win11 本地拉代码

```bash
git clone https://github.com/7coder-li/SDN-DDOS-SYSTEM.git
cd SDN-DDOS-SYSTEM
git branch -a
```

> `git branch -a` 是为了确认默认分支（通常是 `main` 或 `master`）。

### 后续同步最新代码

如果默认分支是 `main`：

```bash
git checkout main
git pull origin main
```

如果你在自己的开发分支（例如 `dev`）：

```bash
git checkout dev
git pull origin dev
```

### 如果你本地已经有目录，但不是 git 仓库

```bash
cd 你的项目目录
git init
git remote add origin https://github.com/7coder-li/SDN-DDOS-SYSTEM.git
git fetch origin
git checkout -b main origin/main
```

### 如果 pull 提示没有上游分支

```bash
git branch --set-upstream-to=origin/main main
git pull
```

## 十一、Win11 + Mininet 虚拟机一条龙联调清单

> 目标：让“训练 -> 在线检测 -> 拦截”完整跑通。  
> 假设：Win11 可以访问虚拟机 `192.168.56.101:8080`（按你实际 IP 修改）。

### A. 虚拟机侧（Ubuntu + Mininet + Ryu）

1) 启动 Ryu（带 northbound REST）

```bash
ryu-manager ryu.app.simple_switch_13 ryu.app.ofctl_rest
```

2) 新开终端，启动 Mininet 拓扑

```bash
sudo mn --topo single,3 --mac --switch ovsk --controller remote
```

3) 在 Mininet 里做连通性测试

```bash
mininet> pingall
```

### B. Win11 侧（后端/模型）

1) 进入项目并安装依赖

```bash
cd SDN-DDOS-SYSTEM
python -m venv .venv
.venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
```

2) 先训练并生成 artifacts（若已有可跳过）

```bash
python ml/train_ddos_rf.py \
  --benign-parquet "../Benign-Monday-no-metadata.parquet" \
  --train-attack-path "../train_set" \
  --test-attack-path "../test_set" \
  --attack-cache-path "../Attack_2019_ALL_FEATURES.parquet" \
  --output-dir "artifacts"
```

3) 验证模型加载与在线预测（可在 Python REPL）

```python
from backend.inference_service import load_service_from_artifacts
service = load_service_from_artifacts("artifacts")
print(service.predict([{
    "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "Protocol": 6,
    "Flow Duration": 300000, "Total Fwd Packets": 20,
    "Total Length of Fwd Packets": 16000, "Total Backward Packets": 1,
    "Total Length of Bwd Packets": 60, "Average Packet Size": 500
}]))
```

4) 调 Ryu 拦截（把 `base_url` 换成虚拟机地址）

```python
from backend.ryu_block_api import RyuBlockAPI
api = RyuBlockAPI(base_url="http://192.168.56.101:8080")
print(api.block_flow(dpid=1, src_ip="10.0.0.1", dst_ip="10.0.0.2", priority=220))
```

### C. 验证“拦截确实生效”

在 Mininet 终端中持续发包（例如 `iperf` / `ping`）后触发 block，再观察：

- 流量是否下降；
- 前端状态是否变为已拦截；
- Ryu 日志是否出现 flowentry add；
- `unblock_flow` 后业务是否恢复。

### D. 最常见三类问题

1. **Win11 调不到 Ryu**：检查虚拟机网卡模式（桥接/Host-only/NAT 端口映射）与 8080 端口。
2. **预测全不对**：检查 `Flow Duration` 是否微秒、在线特征字段名是否与训练一致。
3. **能检测不能拦截**：确认 `dpid` 正确、`ofctl_rest` 已加载、match 字段是否过于严格。
