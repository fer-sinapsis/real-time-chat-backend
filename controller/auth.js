const {response} = require("express");
const Usuario = require("../models/usuario");
const bcrypt = require('bcryptjs');
const {generarJWT} = require("../helpers/jwt");


const crearUsuario = async (req, res = response) => {

  const {email, password} = req.body;

  try {

    const existEmail = await Usuario.findOne({email});

    if (existEmail) {
      return res.status(400).json({ok: false, msg: 'El correo ya esta registrado'})
    }


    const usuario = new Usuario(req.body);


    // Encriptar contraseña
    const salt = bcrypt.genSaltSync();
    usuario.password = bcrypt.hashSync(password, salt);


    await usuario.save();

    // Generar JWT
    const token = await generarJWT(usuario.id);


    res.json({ok: true, usuario, token})


  } catch (error) {
    console.log(error);
    res.status(500).json({ok: false, msg: 'Hable con el administrador'})
  };


}


const login = async (req, res = response) => {

  const {email, password} = req.body;

  try {
    const usuarioDB = await Usuario.findOne({email});

    if (! usuarioDB) {
      return res.status(400).json({ok: false, msg: "Email no encontrado"})
    }

    const validPassword = bcrypt.compareSync(password, usuarioDB.password);

    if (! validPassword) {
      return res.status(400).json({ok: false, msg: "Password no valido"})
    }

    // Generar JWT
    const token = await generarJWT(usuarioDB.id);


    res.json({ok: true, usuario: usuarioDB, token})


  } catch (error) {
    console.log(error);
    res.status(500).json({ok: false, msg: 'Hable con el administrador'})
  }

}


const renewToken = async (req, res = response) => {

    const uid = req.uid

    // Generar JWT
    const token = await generarJWT(uid);

    const usuarioDB = await Usuario.findById(uid);

    if (! usuarioDB) {
      return res.status(400).json({ok: false, msg: "Token no valido"})
    }


    res.json({ok: true, usuario: usuarioDB, token})

};

module.exports = {
  crearUsuario,
  login,
  renewToken
};
