import axios from 'axios';

export async function refreshSpotifyToken(refreshToken, clientId, clientSecret) {
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    try {
        const response = await axios.post(
            'https://accounts.spotify.com/api/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken
            }).toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Basic ${basicAuth}`
                }
            }
        );

        const newAccessToken = response.data.access_token;
        if (!newAccessToken) {
            throw new Error('No access token returned');
        }

        return newAccessToken;
    } catch (error) {
        console.error('Error refreshing Spotify token:', error.response?.data || error.message);
        throw new Error('Failed to refresh token');
    }
}
