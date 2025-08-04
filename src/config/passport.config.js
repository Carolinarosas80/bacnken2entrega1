import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import UserModel from '../dao/models/user.model.js';
import { createHash, isValidPassword } from '../utils/cript.js';
import dotenv from 'dotenv';
dotenv.config();

// REGISTRO
passport.use('register', new LocalStrategy(
  { usernameField: 'email', passReqToCallback: true },
  async (req, email, password, done) => {
    try {
      const { first_name, last_name, age } = req.body;
      const exists = await UserModel.findOne({ email });
      if (exists) return done(null, false, { message: 'Ya existe' });

      const hashedPassword = createHash(password);
      const user = await UserModel.create({
        first_name, last_name, email, age, password: hashedPassword
      });
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// LOGIN
passport.use('login', new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await UserModel.findOne({ email });
      if (!user || !isValidPassword(user, password)) {
        return done(null, false, { message: 'Credenciales inválidas' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// JWT
passport.use('jwt', new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET || 'jwtSecretKey'
}, async (jwtPayload, done) => {
  try {
    return done(null, jwtPayload);
  } catch (error) {
    return done(error);
  }
}));

export default passport;
