/*

  path: /api/auth

*/

const {Router} = require('express');
const { check } = require('express-validator');
const { crearUsuario, login, renewToken } = require('../controller/auth');
const { validarCampos } = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');

const router = Router();


router.post('/new', 
[
  check('nombre', 'El nombre es obligatorio').not().isEmpty(),
  check('email', 'El email es obligatorio').isEmail(),
  check('password', 'El password es obligatorio').not().isEmpty(),
  validarCampos
],
crearUsuario);


//Login User
router.post('/', 
[
  check('email', 'El email es obligatorio').isEmail(),
  check('password', 'El password es obligatorio').not().isEmpty(),
  validarCampos
],
login);

//Review Token
router.get('/renew', validarJWT,  renewToken);





module.exports = router;