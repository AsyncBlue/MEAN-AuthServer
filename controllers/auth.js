const { response } = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async ( req, res = response ) => {
    const { name, email, password } = req.body;
    try {
        //Verificar que noe existe el email
        const usuario = await Usuario.findOne({ email })
        if ( usuario ) {
            return res.status(400).json({
                ok: false,
                msg: 'Usuario ya existe con ese email'
            });
        }
        //Crear usuario con el modelo
        dbUser = new Usuario( req.body );
        //Hashear la contraseña
        const salt = bcrypt.genSaltSync();
        dbUser.password = bcrypt.hashSync( password, salt );
        //Generar el JWT
        const token = await generarJWT( dbUser.id, name );
        //Crear usuario de DB
        await dbUser.save();
        //Generar respuesta exitosa
        return res.status(201).json({
            ok: true,
            uid: dbUser.id,
            name,
            email,
            token
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Por favor hable con el administrador'
        });
    }
}

const loginUsuario = async ( req, res = response ) => {
    const { email, password } = req.body;
    try {
        const dbUser = await Usuario.findOne({ email });
        if ( !dbUser ) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }
        //Confirmar si el password hace match
        const validPasword = bcrypt.compareSync( password, dbUser.password );
        if ( !validPasword ) {
            return res.status(400).json({
                ok: false,
                msg: 'El password es incorrecto'
            });
        }
        // Generar JWT
        const token = await generarJWT( dbUser.id, dbUser.name );
        //Respuesta exitosa
        return res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            token
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Por favor hable con el administrador'
        });
    }
}

const revalidarToken = async ( req, res ) => {
    const { uid } = req;
    //Leer la BD
    const dbUser = await Usuario.findById( uid );
    //Generar JWT
    const token = await generarJWT( uid, dbUser.name );
    return res.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });
}

module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}