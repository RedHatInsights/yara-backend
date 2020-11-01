const util = require('util');
const {Client} = require('pg')
const client = new Client({connectionString: 'postgres://postgres:postgres@localhost:5434/myapp'})
const exec = util.promisify(require('child_process').exec);

const dir = '/home/dkuc/code/rules'


async function startImport() {
    await client.connect()

    const {stdout} = await exec(`find ${dir} -type f -name "*.yar"`);
    for (const file of stdout.trim().split('\n')) {
        console.log(`Attempting to insert ${file}`);
        try {
            const {stdout} = await exec(`plyara ${file}`);
            //console.log(file)
            let parsedRules = JSON.parse(stdout);
            if (parsedRules.length !== 1) {
                console.log(`skipping ${file} because it does not contain a single rule`);
                continue;
            }
            const parsedRule = parsedRules[0];


            //Merge all metadata objects into one dictionary
            const metadata = Object.assign.apply(Object, parsedRule.metadata);

            const res = await client.query('INSERT INTO rule (name, tags, metadata, raw_rule) VALUES ($1,$2,$3,$4)',
                [parsedRule.rule_name, parsedRule.tags, metadata, stdout])


        } catch (e) {
            console.error(`${file} failed. ${e.message}`)
        }


    }

    await client.end()

}

startImport().catch(e => console.error(e));
