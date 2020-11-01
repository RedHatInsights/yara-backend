### For frontend devs:
`docker-compose up`

### For backend devs
``` bash
npm install
cp .env.example .env
docker-compose up -d db
graphile-migrate watch
```
Then in a new console
```
node --require ts-node/register src/app.ts
```

### Interacting with the API
The api browser will be available at http://localhost:3000/graphiql

The actual api will be on http://localhost:3000/graphql
