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
