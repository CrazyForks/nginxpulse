FROM node:20-alpine AS webapp-builder

WORKDIR /app
COPY webapp/package*.json ./webapp/
RUN cd webapp && npm install

COPY webapp ./webapp
RUN cd webapp && npm run build

FROM golang:1.23.6-alpine AS backend-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG BUILD_TIME
ARG GIT_COMMIT
ARG VERSION
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w -X 'github.com/likaia/nginxpulse/internal/version.Version=${VERSION}' -X 'github.com/likaia/nginxpulse/internal/version.BuildTime=${BUILD_TIME}' -X 'github.com/likaia/nginxpulse/internal/version.GitCommit=${GIT_COMMIT}'" \
    -o /out/nginxpulse ./cmd/nginxpulse/main.go

FROM nginx:1.27-alpine AS runtime

WORKDIR /app
ARG BUILD_TIME
ARG GIT_COMMIT
ARG VERSION
RUN apk add --no-cache su-exec \
    && addgroup -S nginxpulse \
    && adduser -S nginxpulse -G nginxpulse

COPY --from=backend-builder /out/nginxpulse /app/nginxpulse
COPY entrypoint.sh /app/entrypoint.sh
COPY docs/external_ips.txt /app/assets/external_ips.txt
COPY --from=webapp-builder /app/webapp/dist /usr/share/nginx/html
COPY configs/nginx_frontend.conf /etc/nginx/conf.d/default.conf
RUN mkdir -p /app/var/nginxpulse_data /app/assets \
    && chown -R nginxpulse:nginxpulse /app \
    && chmod +x /app/entrypoint.sh

LABEL org.opencontainers.image.title="nginxpulse" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_TIME}"
EXPOSE 8088 8089
ENTRYPOINT ["/app/entrypoint.sh"]
