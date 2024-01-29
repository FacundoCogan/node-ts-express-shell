//! OBJETIVO DE DTO: AL RECIBIR UN OBJETO DE TIPO DTO, PODER 
//! CONFIAR EN SUS PROPIEDADES

import { regularExps } from "../../../config";

export class LoginUserDto{

    private constructor(
        public readonly email:string,
        public readonly password:string
    ){}

    static create(object: {[key:string]:any}): [string?, LoginUserDto?] {
        const {email, password} = object;

        if(!email) return ['Missing email'];
        if(!regularExps.email.test(email)) return ['Email is not valid'];
        if(!password) return ['Missing password'];
        if(password.length < 6) return ['Password must be at least 6 characters'];

        return [undefined, new LoginUserDto(email, password)];

    }

}

