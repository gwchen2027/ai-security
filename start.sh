#!/bin/bash
# AI漏洞防护与扫毒系统 - 启动脚本

echo "=========================================="
echo "  AI漏洞防护与扫毒系统"
echo "  AI Security Scanner & Antivirus v1.0.0"
echo "=========================================="
echo ""

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "❌ 未找到Python3，请先安装Python3.8+"
    exit 1
fi

echo "✅ Python版本: $(python3 --version)"

# 进入应用目录
cd "$(dirname "$0")"

# 安装依赖（如果需要）
echo "📦 检查依赖..."
pip3 install --break-system-packages flask flask-cors watchdog 2>/dev/null || \
pip3 install flask flask-cors watchdog 2>/dev/null || \
echo "⚠️  依赖安装可能失败，请手动安装: pip install flask flask-cors watchdog"

echo ""
echo "🚀 启动应用..."
echo "📡  访问地址: http://0.0.0.0:5000"
echo "📡  本地访问: http://127.0.0.1:5000"
echo ""
echo "按 Ctrl+C 停止服务"
echo "=========================================="
echo ""

python3 app.py
