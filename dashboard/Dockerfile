# Build the React app
FROM node:24-alpine AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10 --activate
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
# Set to "true" to build with simulated demo data instead of the real API
ARG VITE_USE_MOCK_API=false
ENV VITE_USE_MOCK_API=$VITE_USE_MOCK_API
RUN pnpm build

# Serve the static files; nginx also forwards /api to the backend
FROM nginx:1.29-alpine
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
# The backend's address inside the Docker Compose network
ENV API_UPSTREAM=http://api:8000
EXPOSE 80
