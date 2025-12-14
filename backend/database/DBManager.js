import sqlite3 from 'sqlite3';
import fs from 'fs';

class DBManager {
    constructor() {
        let db_setup = fs.existsSync("db.sqlite");

        this.db = new sqlite3.Database('db.sqlite');
        if (!db_setup) {
            this.createNewDB();
        }
    }

    createNewDB() {
        const schema = fs.readFileSync('./database/schema.sql', 'utf8');
        this.db.exec(schema);
    }

    execute(query, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(query, params, function(err) {
                if (err) {
                    return reject(err);
                }
                resolve(this);
            });
        });
    }

    queryAll(query, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(query, params, (err, rows) => {
                if (err) {
                    return reject(err);
                }
                resolve(rows);
            });
        });
    }

    queryGet(query, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(query, params, (err, row) => {
                if (err) {
                    return reject(err);
                }
                resolve(row);
            });
        });
    }
}

export default DBManager;