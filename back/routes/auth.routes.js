const router = require('express').Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 15;

router.post('/signup', async (req, res, next) => {
  /* Get back the payload from your request, as it's a POST you can access req.body */
  const payload = req.body;
  /* Hash the password using bcryptjs */
  const salt = bcrypt.genSaltSync(SALT_ROUNDS);
  const passwordHash = bcrypt.hashSync(payload.password, salt);
  /* Record your user to the DB */
  const userToRegister = { email: payload.email, passwordHash };
  try {
    const newUser = await UserActivation.create(userToRegister);
    res.status(201).json({ message: 'User created', newUser });
  } catch (error) {
    console.log(error);
    res.status(500).json(error);
  }
})

router.post('/login', async (req, res, next) => {
  /* Get back the payload from your request, as it's a POST you can access req.body */
  const payload = req.body;
  /* Try to get your user from the DB */
  try {
    const potentialUser = await UserActivation.findOne({ email: payload.email.toLowerCase().trim() });
  /* If your user exists, check if the password is correct */
    if (potentialUser) {
      if (bcrypt.compareSync(payload.password, potentialUser.passwordHash)) {
  /* If your password is correct, sign the JWT using jsonwebtoken */   
        const authToken = jwt.sign(
          {
            userId: potentialUser._id,            
          }, 
          process.env.TOKEN_SECRET,
          {
            algorithm: 'HS256',
            expiresIn: '8h',
          }
        )
        res.status(200).json({ token: authToken });
      }
      }
      else {
        res.status(403).json({ message: 'Wrong Password' });
      }
    else {
      res.status(404).json({ message: ' Wrong User' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json(error);
  }  
})

router.get('/verify', (req, res, next) => {
  // You need to use the middleware there, if the request passes the middleware, it means your token is good
  res.json('Pinging verify')
})

module.exports = router
