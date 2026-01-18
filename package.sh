#!/bin/bash

echo "开始构建 NginxPulse..."
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

if [ -f "webapp/package.json" ]; then
    echo "构建前端资源..."
    (cd webapp && npm install && npm run build) || {
        echo "前端构建失败!"
        exit 1
    }
fi

echo "清理旧文件..."
mkdir -p bin
rm -f bin/nginxpulse

# 获取版本信息
BUILD_TIME=$(date "+%Y-%m-%d %H:%M:%S")
GIT_COMMIT=$(git rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo "dev")}

echo "版本信息:"
echo " - 版本号: ${VERSION}"
echo " - 构建时间: ${BUILD_TIME}"
echo " - Git提交: ${GIT_COMMIT}"

echo "编译主程序..."
go build -ldflags="-s -w -X 'github.com/likaia/nginxpulse/internal/version.Version=${VERSION}' -X 'github.com/likaia/nginxpulse/internal/version.BuildTime=${BUILD_TIME}' -X 'github.com/likaia/nginxpulse/internal/version.GitCommit=${GIT_COMMIT}'" -o bin/nginxpulse ./cmd/nginxpulse/main.go

if [ $? -eq 0 ]; then
    echo "构建成功! 可执行文件: bin/nginxpulse"

    # 显示文件大小
    FILE_SIZE=$(du -h bin/nginxpulse | cut -f1)
    echo "文件大小: ${FILE_SIZE}"

    # 检查是否正确嵌入了资源
    echo "验证资源嵌入..."
    strings bin/nginxpulse | grep -q "<!DOCTYPE html>" && echo "✓ HTML资源已嵌入" || echo "✗ HTML资源可能未正确嵌入"
    strings bin/nginxpulse | grep -q ".css" && echo "✓ CSS资源已嵌入" || echo "✗ CSS资源可能未正确嵌入"
    strings bin/nginxpulse | grep -q ".js" && echo "✓ JS资源已嵌入" || echo "✗ JS资源可能未正确嵌入"

    echo "构建完成，可执行文件已准备就绪"
else
    echo "构建失败!"
    exit 1
fi
