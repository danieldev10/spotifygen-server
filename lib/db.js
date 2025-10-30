import mysql from 'mysql2/promise';

let connection;

export const connectToDatabase = async () => {
    if (!connection) {
        connection = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: '',
            database: 'rnmauth'
        });
    }

    return connection;
}