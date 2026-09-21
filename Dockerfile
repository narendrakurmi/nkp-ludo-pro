FROM node:18-alpine

WORKDIR /app

# Copy package.json first (for caching)
COPY package.json ./

# Install dependencies
RUN npm install --omit=dev 2>/dev/null || true

# Copy server code
COPY server.js ./

# Expose port (Render.com uses this)
EXPOSE 3000

# Environment variables (set on Render.com dashboard)
# RAZORPAY_KEY_ID
# RAZORPAY_KEY_SECRET

CMD ["node", "server.js"]
