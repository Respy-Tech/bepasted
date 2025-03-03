FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy app source
COPY src/ ./src/
COPY public/ ./public/
COPY openapi.json ./openapi.json
COPY openapi.yaml ./openapi.yaml

# Create .env file if it doesn't exist (will be overridden by mounted volumes in production)
RUN touch .env

# Expose the port the app runs on
EXPOSE 3000

# Define the command to run the app
CMD ["node", "src/index.js"] 