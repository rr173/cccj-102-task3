#!/usr/bin/env bash
# 防篡改凭证册一键复现：
#   1) 离线单元测试（密码学/链/锚点/换代/篡改/增量/留存/对账）
#   2) 7 场景真实双进程验收（空白账库 + 故障注入 + 离线核验器）
# 产物：cred-acceptance-report.json（结构化报告）
set -euo pipefail
cd "$(dirname "$0")"

echo "== [1/2] 离线单元测试 =="
python3 -m unittest whub.test_core whub.test_cred -v

echo
echo "== [2/2] 凭证册 7 场景真实双进程验收 =="
python3 -m whub cred-acceptance --report cred-acceptance-report.json "$@"

echo
echo "完成。结构化报告：$(pwd)/cred-acceptance-report.json"
