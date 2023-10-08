FROM node:lts-alpine3.18

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Bundle app source
COPY . .

# Set Environment
ENV NODE_ENV="production"

EXPOSE 80
CMD [ "node", "index.js" ]