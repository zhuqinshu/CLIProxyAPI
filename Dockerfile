FROM golang:1.24-alpine AS builder

ENV GOPROXY=https://mirrors.cloud.tencent.com/go/,direct

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o ./CLIProxyAPI ./cmd/server/

FROM alpine:3.22.0

# 修改镜像源（在 apk add 之前）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.cloud.tencent.com/g' /etc/apk/repositories

RUN apk add --no-cache tzdata ca-certificates

RUN mkdir -p /CLIProxyAPI/static

WORKDIR /CLIProxyAPI

# 复制二进制文件并设置权限
COPY --from=builder /app/CLIProxyAPI /CLIProxyAPI/CLIProxyAPI
RUN chmod +x /CLIProxyAPI/CLIProxyAPI

# 复制配置文件（两份：example 和默认）
COPY config.example.yaml /CLIProxyAPI/config.example.yaml
COPY config.example.yaml /CLIProxyAPI/config.yaml

# 复制静态文件
COPY static/ /CLIProxyAPI/static/ 2>/dev/null || true

# 设置环境变量
ENV TZ=Asia/Shanghai
ENV PORT=8317

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

EXPOSE 8317

# 启动命令 - 如果应用需要指定配置文件，使用下面注释的版本
CMD ["./CLIProxyAPI"]
# CMD ["./CLIProxyAPI", "--config", "config.yaml"]