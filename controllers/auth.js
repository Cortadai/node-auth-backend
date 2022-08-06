const {response, request}=require("express");
const Usuario = require("../models/Usuario");
const bcrypt = require("bcryptjs");
const {generarJWT}= require("../helpers/jwt");

const crearUsuario = async(req=request, res=response)=>{
    
    const { name, email, password} = req.body;

    try {
        // Verificar el email
        const usuario = await Usuario.findOne({email});
        if(usuario){
            return res.status(400).json({      // BAD request
                ok:false,
                msg:"Ya existe un usuario con ese email"
            })
        }

        // Crear usuario con el modelo
        const dbUser = new Usuario(req.body);

        // Hashear (encriptar) la contraseña
        const salt = bcrypt.genSaltSync();
        dbUser.password=bcrypt.hashSync(password, salt);

        // Generar el JWT
        const token = await generarJWT(dbUser.id, name);

        // Crear usuario BD
        dbUser.save();

        // Generar respuesta exitosa
        return res.status(201).json({     // Se creo un nuevo registro
            ok:true,
            uid: dbUser.id,
            name,
            token
        });     
        
    } catch (error) {
        return res.status(500).json({   // Error Servidor
            ok:false,
            msg:"Por favor, hable con el administrador"
        }) 
    }

}

const loginUsuario = async(req=request, res=response)=>{

    const { email, password} = req.body;

    try {
        
        // Verificar el email
        const dbUser = await Usuario.findOne({email});
        if(!dbUser){
            return res.status(400).json({
                ok:false,
                msg:"El correo no exite"
            })
        }

        // Confirmar si el password hace match
        const validPassword = bcrypt.compareSync(password, dbUser.password);
        if(!validPassword){
            return res.status(400).json({
                ok:false,
                msg:"El password no es valido"
            })
        }

        // Generar el JWT
        const token = await generarJWT(dbUser.id, dbUser.name);
        
        // Generar respuesta exitosa
        return res.json({     // Se hizo login existosamente
            ok:true,
            uid: dbUser.id,
            name: dbUser.name,
            token
        });  

    } catch (error) {
        console.log(error);
        return res.status(500).json({   // Error Servidor
            ok:false,
            msg:"Por favor, hable con el administrador"
        });
    }

}

const revalidarToken = async(req=request, res=response)=>{
    
    const {uid, name} = req;

    // Generar nuevo JWT
    const token = await generarJWT(uid, name);

    return res.json({
        ok:true,
        uid,
        name,
        token
    })

}


module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken
}