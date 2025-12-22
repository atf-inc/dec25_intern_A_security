
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source
COPY . .

# Build
RUN npm run build

# Expose port (Frontend runs on 3001 typically, but Next.js defaults to 3000. 
# We will use PORT env var or command to switch to 3001 if needed, 
# but internally docker containers can just use 3000 and map to 3001 on host.
# However, to avoid confusion, let's keep it 3000 inside and map in compose.)
EXPOSE 3000

# Start
CMD ["npm", "start"]