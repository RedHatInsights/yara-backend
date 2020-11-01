FROM node:12

WORKDIR /usr/src/app
ENV PATH /usr/src/app/node_modules/.bin:$PATH
RUN npm install typescript -g

COPY package*.json ./

RUN npm ci --only=production

COPY . .
RUN tsc

EXPOSE 3000
CMD [ "node", "src/app.js" ]
