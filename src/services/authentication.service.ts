import {User} from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import {Buffer} from "buffer"; // Pour décoder Base64
import {notFound} from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key"; // Clé secrète pour signer le token

export class AuthenticationService {
    public async authenticate(
        username: string,
        password: string
    ): Promise<string> {
        // Recherche l'utilisateur dans la base de données
        const user = await User.findOne({where: {username}});

        if (!user) {
            throw notFound("User");
        }

        // Décoder le mot de passe stocké en base de données
        const decodedPassword = Buffer.from(user.password, "base64").toString(
            "utf-8"
        );

        // Vérifie si le mot de passe est correct
        if (password === decodedPassword) {

            const role = user.username;

            const defaultScope: { [key: string]: boolean } = {
                'book:read': true
            };

            const adminScope: { [key: string]: boolean } = {
                'user:read': true,
                'user:write': true,
                'user:delete': true,
                'user:update': true,
                'author:read': true,
                'author:write': true,
                'author:delete': true,
                'author:update': true,
                'book:read': true,
                'book:write': true,
                'book:delete': true,
                'book:update': true,
                'bookCollection:read': true,
                'bookCollection:write': true,
                'bookCollection:delete': true,
                'bookCollection:update': true
            };

            let scope = { ...defaultScope };

            if (role === 'admin') {
                scope = { ...scope, ...adminScope };
            }

            // Si l'utilisateur est authentifié, on génère un JWT
            const token = jwt.sign({username: user.username, scopes: scope}, JWT_SECRET, {
                expiresIn: "1h",
            });
            return token;
        } else {
            let error = new Error("Wrong password");
            (error as any).status = 403;
            throw error;
        }
    }
}

export const
    authService = new AuthenticationService();
