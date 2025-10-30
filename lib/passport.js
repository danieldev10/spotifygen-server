import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as SpotifyStrategy } from 'passport-spotify';
import { connectToDatabase } from './db.js';

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const connection = await connectToDatabase();
        let [rows] = await connection.query('SELECT * FROM users WHERE googleId = ?', [profile.id]);
        let user = rows[0];
        if (!user) {
            [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [profile.emails[0].value]);
            user = rows[0];
            if (user) {
                await connection.query('UPDATE users SET googleId = ? WHERE id = ?', [profile.id, user.id]);
            } else {
                await connection.query(
                    'INSERT INTO users (username, email, googleId) VALUES (?, ?, ?)',
                    [profile.displayName, profile.emails[0].value, profile.id]
                );
                [rows] = await connection.query('SELECT * FROM users WHERE googleId = ?', [profile.id]);
                user = rows[0];
            }
        }
        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

passport.use(new SpotifyStrategy({
    clientID: process.env.SPOTIFY_CLIENT_ID,
    clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
    callbackURL: 'http://127.0.0.1:3000/auth/spotify/callback'
}, async (accessToken, refreshToken, expires_in, profile, done) => {
    try {
        const connection = await connectToDatabase();

        let [rows] = await connection.query('SELECT * FROM users WHERE spotifyId = ?', [profile.id]);
        let user = rows[0];

        if (user) {
            // ✅ Update tokens for existing user
            await connection.query(
                'UPDATE users SET spotifyAccessToken = ?, spotifyRefreshToken = ? WHERE id = ?',
                [accessToken, refreshToken, user.id]
            );
        } else {
            [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [profile.emails[0].value]);
            user = rows[0];

            if (user) {
                // ✅ Update Spotify ID and tokens
                await connection.query(
                    'UPDATE users SET spotifyId = ?, spotifyAccessToken = ?, spotifyRefreshToken = ? WHERE id = ?',
                    [profile.id, accessToken, refreshToken, user.id]
                );
            } else {
                // ✅ New user, insert everything
                await connection.query(
                    'INSERT INTO users (username, email, spotifyId, spotifyAccessToken, spotifyRefreshToken) VALUES (?, ?, ?, ?, ?)',
                    [profile.displayName, profile.emails[0].value, profile.id, accessToken, refreshToken]
                );
                [rows] = await connection.query('SELECT * FROM users WHERE spotifyId = ?', [profile.id]);
                user = rows[0];
            }
        }

        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

export default passport;
