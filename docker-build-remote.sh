#!/usr/bin/env bash
#
# docker-build-remote.sh - 使用 Docker Context 在远程服务器构建镜像
#
# 此脚本使用 Docker context 在远程 SSH 服务器 (tx) 上构建镜像
# 镜像名称: eceasy/cli-proxy-api:latest

set -euo pipefail

# 配置
DOCKER_CONTEXT="tx"
IMAGE_NAME="eceasy/cli-proxy-api:latest"

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 Docker context 是否存在
check_docker_context() {
    echo_info "检查 Docker context '${DOCKER_CONTEXT}' 是否存在..."
    if ! docker context ls | grep -q "^${DOCKER_CONTEXT} "; then
        echo_error "Docker context '${DOCKER_CONTEXT}' 不存在"
        echo_info "请先创建 Docker context，例如："
        echo "  docker context create ${DOCKER_CONTEXT} --docker \"host=ssh://user@hostname\""
        exit 1
    fi
    echo_info "Docker context '${DOCKER_CONTEXT}' 已找到"
}

# 获取版本信息
get_version_info() {
    VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')"
    COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'none')"
    BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    echo_info "构建信息:"
    echo "  版本: ${VERSION}"
    echo "  提交: ${COMMIT}"
    echo "  构建日期: ${BUILD_DATE}"
    echo "  镜像名称: ${IMAGE_NAME}"
    echo "  Docker Context: ${DOCKER_CONTEXT}"
    echo "----------------------------------------"
}

# 在远程服务器上构建镜像
build_image() {
    echo_info "开始在远程服务器 '${DOCKER_CONTEXT}' 上构建镜像..."
    
    docker --context "${DOCKER_CONTEXT}" build \
        --build-arg VERSION="${VERSION}" \
        --build-arg COMMIT="${COMMIT}" \
        --build-arg BUILD_DATE="${BUILD_DATE}" \
        -t "${IMAGE_NAME}" \
        -f Dockerfile \
        .
    
    if [ $? -eq 0 ]; then
        echo_info "镜像构建成功: ${IMAGE_NAME}"
    else
        echo_error "镜像构建失败"
        exit 1
    fi
}

# 验证镜像是否存在
verify_image() {
    echo_info "验证远程服务器上的镜像..."
    if docker --context "${DOCKER_CONTEXT}" images | grep -q "${IMAGE_NAME}"; then
        echo_info "镜像验证成功"
        docker --context "${DOCKER_CONTEXT}" images | grep "eceasy/cli-proxy-api"
    else
        echo_warn "未找到镜像，但构建可能成功"
    fi
}

# 主流程
main() {
    echo_info "=== 开始远程 Docker 构建 ==="
    
    check_docker_context
    get_version_info
    
    read -p "是否继续构建? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo_warn "构建已取消"
        exit 0
    fi
    
    build_image
    verify_image
    
    echo_info "=== 构建完成 ==="
    echo_info "你可以使用以下命令查看远程镜像:"
    echo "  docker --context ${DOCKER_CONTEXT} images"
    echo_info "或者在远程服务器上运行:"
    echo "  docker --context ${DOCKER_CONTEXT} run -d -p 8317:8317 ${IMAGE_NAME}"
}

main "$@"
