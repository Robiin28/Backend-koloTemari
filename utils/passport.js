const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('./../models/UserModel');

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_REDIRECT_URI,
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user already exists (by googleId or email)
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        // If not found by googleId, try email
        user = await User.findOne({ email: profile.emails[0].value });
      }
      if (!user) {
        // Create new user consistent with your signup pattern
        user = new User({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value,
          active: true   // Since user is verified by Google
          // Add other fields as per your user schema
        });
        await user.save();
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => { 
  const user = await User.findById(id); 
  done(null, user);
});
