import { Service } from "@kronos-integration/service";


export class AuthSource extends Service {

    static get endpoints() {
        return {
            ...super.endpoints,
            authenticate: {
                default: true,
                receive: "authenticate"
            }
        };
    }

    async authenticate(credentials) {
        const { username, password } = credentials;

        if (password !== "test") {
            throw new Error('invalid credentials');
        }
        const response = { username, entitlements: new Set(['a', 'b']) };
        return response;
    }
}

export default AuthSource;
