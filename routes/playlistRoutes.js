import express from 'express';
import { connectToDatabase } from '../lib/db.js';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { analyzePromptWithMistral } from "../lib/mistralUtils.js";
import { refreshSpotifyToken } from '../lib/spotifyUtils.js';

const router = express.Router();

const getArtistIds = async (artistNames, accessToken) => {
    const artistIds = [];

    for (const name of artistNames) {
        try {
            const res = await axios.get(`https://api.spotify.com/v1/search`, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                },
                params: {
                    q: name,
                    type: 'artist',
                    limit: 5,
                },
            });

            const artists = res.data.artists.items;

            const exactMatch = artists.find(artist => artist.name.toLowerCase() === name.toLowerCase());

            if (exactMatch) {
                artistIds.push(exactMatch.id);
            } else if (artists.length > 0) {

                artistIds.push(artists[0].id);
            } else {
                console.warn(`No artist found for: ${name}`);
            }
        } catch (err) {
            console.error(`Error fetching artist ID for: ${name}`, err.response?.data || err.message);
        }
    }

    return artistIds;
};



const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(403).json({ message: "No or invalid token provided" })
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(403).json({ message: "No token provided" })
        }
        const decoded = jwt.verify(token, process.env.JWT_KEY);
        const connection = await connectToDatabase();
        const [rows] = await connection.query('SELECT * FROM users WHERE id = ?', [decoded.id]);
        if (!rows.length) return res.status(401).json({ message: 'Invalid token' });
        if (
            rows[0].passwordChangedAt &&
            new Date(rows[0].passwordChangedAt).getTime() > decoded.iat * 1000
        ) {
            return res.status(401).json({ message: 'Token is no longer valid.' });
        }
        req.userId = decoded.id;
        next();
    } catch (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: "Invalid or expired token" })
    }
};

router.post('/generate-playlist', verifyToken, async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ message: "Prompt is required" });

    try {
        const connection = await connectToDatabase();
        const [rows] = await connection.query('SELECT * FROM users WHERE id = ?', [req.userId]);
        const user = rows[0];
        let accessToken = user.spotifyAccessToken;
        const refreshToken = user.spotifyRefreshToken;

        try {
            await axios.get("https://api.spotify.com/v1/me", {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
        } catch (err) {
            if (err.response?.status === 401 && refreshToken) {
                console.log("Refreshing Spotify token...");
                accessToken = await refreshSpotifyToken(
                    refreshToken,
                    process.env.SPOTIFY_CLIENT_ID,
                    process.env.SPOTIFY_CLIENT_SECRET
                );
                await connection.query(
                    "UPDATE users SET spotifyAccessToken=? WHERE id=?",
                    [accessToken, req.userId]
                );
            } else {
                throw err;
            }
        }

        const aiData = await analyzePromptWithMistral(prompt);
        const playlistName = aiData.title || prompt.slice(0, 50);
        const genres = aiData.genres || ["pop"];
        const artists = aiData.artists || [];

        const playlistRes = await axios.post(
            `https://api.spotify.com/v1/users/${user.spotifyId}/playlists`,
            {
                name: playlistName,
                description: `Generated Playlist from RECTIFY`,
                public: false
            },
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const playlistId = playlistRes.data.id;

        let uris = [];
        for (const genre of genres) {
            const searchRes = await axios.get('https://api.spotify.com/v1/search', {
                params: { q: `genre:${genre}`, type: 'track', limit: 10 },
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            uris.push(...searchRes.data.tracks.items.map(t => t.uri));
        }
        for (const artist of artists) {
            const searchRes = await axios.get('https://api.spotify.com/v1/search', {
                params: { q: `artist:${artist}`, type: 'track', limit: 5 },
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            uris.push(...searchRes.data.tracks.items.map(t => t.uri));
        }

        // Deduplicate and limit to ~30 songs
        uris = [...new Set(uris)].slice(0, 30);

        // 🎶 Add tracks
        if (uris.length) {
            await axios.post(
                `https://api.spotify.com/v1/playlists/${playlistId}/tracks`,
                { uris },
                { headers: { Authorization: `Bearer ${accessToken}` } }
            );
        }

        return res.status(201).json({
            message: 'Playlist created!',
            playlistId,
            playlistName,
            genres,
            artists
        });
    } catch (err) {
        console.error('Playlist generation error:', err.response?.data || err.message);
        res.status(500).json({ message: 'Failed to create playlist' });
    }
});

export default router;