## For frontend devs:
`docker-compose up --build`
#### To reset to a fresh db:
`docker-compose down && docker-compose up --build`
#### To seed with prod rules:
`PROD=true docker-compose up --build`

## For backend devs
```bash
npm install
cp .env.example .env
export $(xargs <.env)
docker-compose up -d db
tsc
npm run migrate
npm run seed-prod
node --require ts-node/register src/app.ts
```

### Interacting with the API
The api browser will be available at http://localhost:3000/graphiql

The actual api will be on http://localhost:3000/graphql

### To reset all state - start fresh
```bash
docker-compose down
```

