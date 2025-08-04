import { Router } from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { passportCall } from '../middlewares/passportCall.js';

const router = Router();

router.post('/register', passport.authenticate('register', { session: false }), (req, res) => {
  res.json({ message: 'Usuario registrado exitosamente' });
});

router.post('/login', passport.authenticate('login', { session: false }), (req, res) => {
  const user = req.user;
  const token = jwt.sign({ user }, process.env.JWT_SECRET || 'jwtSecretKey', { expiresIn: '1h' });
  res.json({ token });
});

router.get('/current', passportCall('jwt'), (req, res) => {
  res.json({ user: req.user.user });
});

export default router;
