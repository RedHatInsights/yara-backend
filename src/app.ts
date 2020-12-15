import dotenv = require('dotenv');
dotenv.config();
import express = require('express');
import {postgraphile, PostGraphileOptions} from 'postgraphile';
import bodyParser = require('body-parser');
import {Request, Response, NextFunction} from "express";
import morgan = require('morgan');
import helmet = require('helmet');

declare module 'express' {
    export interface Request {
        account?: string
        host_uuid?: string
    }
}

const app = express();


app.use(helmet());
app.use(morgan('tiny'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.text({ type: 'application/graphql' }));


function authMiddleware(req: Request, res: Response, next: NextFunction) {
    const identityHeader = req.headers["x-rh-identity"];

    /*if(typeof identityHeader != 'string')
        return res.status(401).end('No identity header')*/

    if(typeof identityHeader != 'string'){// Temporary - For development only
        req.account = '540155';
        req.host_uuid = '00000000-0000-0000-0000-000000000000';
        return next();
    }


    const identityString = Buffer.from(identityHeader, 'base64').toString('utf-8');
    const identity = JSON.parse(identityString);
    req.account = identity.identity.account_number;
    req.host_uuid = identity.identity?.system?.cn;
    next();
}

app.use("/graphql", authMiddleware);

const options: PostGraphileOptions = {
    subscriptions: true,
    watchPg: true,
    dynamicJson: true,
    setofFunctionsContainNulls: false,
    ignoreRBAC: false,
    ignoreIndexes: false,
    showErrorStack: "json",
    extendedErrors: ["hint", "detail", "errcode"],
    appendPlugins: [require("@graphile-contrib/pg-simplify-inflector")],
    exportGqlSchemaPath: "schema.graphql",
    simpleCollections: "both",
    graphiql: true,
    enhanceGraphiql: true,
    allowExplain(req) {
        // TODO: customise condition!
        return true;
    },
    enableQueryBatching: true,
    legacyRelations: "omit",
    pgSettings(req) {
        return{
            'role':'yara_user',
            'insights.account': (<Request>req).account,
            'insights.host_uuid': (<Request>req).host_uuid
        }
    },
    ownerConnectionString: process.env.OWNER_URL
};
const database: string = process.env.DATABASE_URL || 'postgraphile';
const schemas: string[] = ['public'];
const graphile = postgraphile(database, schemas, options);

app.use(graphile);

const server = app.listen(3000, () => {
    const address = server.address();
    if (typeof address !== 'string') {
        // @ts-ignore
        const href = `http://localhost:${address.port}${options.graphiqlRoute || '/graphiql'}`;
        console.log(`PostGraphiQL available at ${href} 🚀`);
    } else {
        console.log(`PostGraphile listening on ${address} 🚀`);
    }
});
