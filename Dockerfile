# stdio MCP server for GrindFree agent-security APIs.
# The caller's Base USDC wallet is supplied at runtime via X402_PRIVATE_KEY
# (or PRIVATE_KEY). Never bake a key into the image.
FROM node:22-alpine

WORKDIR /app

COPY mcp-server/package.json mcp-server/package-lock.json ./
RUN npm ci --omit=dev

COPY mcp-server/src ./src
COPY LICENSE README.md server.json ./

ENV NODE_ENV=production
USER node

ENTRYPOINT ["node", "src/index.js"]
