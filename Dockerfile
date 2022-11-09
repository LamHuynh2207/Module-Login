FROM node:18.12.0-alpine3.

WORKDIR /server

COPY package*.json .

RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "run", "start"]