# Naive Bayes 实验

本目录包含 Naive Bayes 模型的 P4 数据平面代码 (`switch/`) 和 C 控制平面代码 (`ctrl/`)。

## 快速运行

请在 `root` 权限下运行：

1. **编译并运行控制器**
   ```bash
   make
   ./naive_bayes_ctrl
   ```
   > 该命令会自动编译 P4 程序、加载到 Tofino 芯片、读取 `naive_bayes_model.txt` 并下发所有流表项。

2. **验证状态**
   程序启动后，您可以在另一个终端通过 `bfshell` 查看端口状态或计数器：
   ```bash
   source ~/bf-sde-9.13.0/set_sde.bash
   bfshell
   ucli
   pm
   show
   ```

## 目录结构
- `switch/`: P4 源代码
- `ctrl/`: 控制器源代码 (C语言)
- `naive_bayes_model.txt`: 训练好的模型参数文件