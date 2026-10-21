FROM oven/bun:1 AS build
WORKDIR /src
COPY package.json bun.lock ./
COPY packages/adapters/ts ./packages/adapters/ts
COPY apps/demo-react/package.json ./apps/demo-react/package.json
RUN bun install
COPY packages/ui/react ./packages/ui/react
COPY apps/demo-react ./apps/demo-react
RUN cd apps/demo-react && bunx vite build

FROM oven/bun:1
WORKDIR /app
COPY --from=build /src /app
WORKDIR /app/apps/demo-react
EXPOSE 5173
CMD ["bun", "server.ts"]
