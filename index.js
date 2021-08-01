const express = require('express');
const cors = require('cors');
const { dbConnection } = require('./db/config');
require('dotenv').config();

//Crear el servidor/aplicacion de express
const app = express();

//Conexion Base de Datos
dbConnection();

//Directorio publico
app.use( express.static('public') );

//Lectura y parseo del BODY
app.use( express.json() );

//Rutas
app.use( '/api/auth', require('./routes/auth') );

//CORS
app.use( cors() );

app.listen( process.env.PORT, () => {
    console.log(`Servidor corriendo en puerto ${ process.env.PORT }`)
});