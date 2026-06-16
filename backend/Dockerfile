FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer cache)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source
COPY src/ ./src/

# Non-root user (security best practice)
RUN addgroup -S passguard && adduser -S passguard -G passguard
USER passguard

EXPOSE 4000

CMD ["node", "src/server.js"]
