import express from 'express';
import cors from 'cors';
import authRouter from './routes/authRoutes.js'
import session from 'express-session';
import passport from './lib/passport.js';
import playlistRouter from './routes/playlistRoutes.js';

const app = express();

app.use(cors({
    origin: 'http://localhost:5173', // Change to frontend origin in production
    credentials: true
}));
app.use(express.json());
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.headers.host + req.url);
        }
        next();
    });
}
app.use(session(
    {
        secret: process.env.GOOGLE_CLIENT_SECRET,
        resave: false,
        saveUninitialized: false
    },
));
app.use(passport.initialize());
app.use(passport.session());
app.use('/auth', authRouter);
app.use('/api', playlistRouter);

app.listen(process.env.PORT, () => {
    console.log("Server is running on port " + process.env.PORT);
})