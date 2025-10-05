const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('./../models/UserModel');

const FRONTEND_URL = process.env.FRONTEND_URL; // e.g., https://your-frontend.vercel.app

// ---------------- Google Strategy ----------------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_REDIRECT_URI,
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          active: true
        });
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// ---------------- GitHub Strategy ----------------
passport.use(new GitHubStrategy({
    clientID: process.env.GIT_CLIENT_ID,
    clientSecret: process.env.GIT_CLIENT_SECRET,
    callbackURL: process.env.GIT_REDIRECT_URL,
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
      if (!user) user = await User.findOne({ email: profile.emails?.[0]?.value });
      if (!user) {
        user = await User.create({
          githubId: profile.id,
          name: profile.username || profile.displayName,
          email: profile.emails?.[0]?.value || null,
          active: true
        });
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// ---------------- Serialize / Deserialize ----------------
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});



module.exports = passport;
