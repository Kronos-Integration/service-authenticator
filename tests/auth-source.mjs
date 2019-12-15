import { Service } from "@kronos-integration/service";

export class AuthSource extends Service {
  static get endpoints() {
    return {
      ...super.endpoints,
      authenticate: {
        receive: "authenticate"
      }
    };
  }

  async authenticate(credentials) {
    const { username, password } = credentials;

    if (password !== "test") {
      throw new Error("invalid credentials");
    }
    return { username, entitlements: new Set(["a", "b"]) };
  }
}

export default AuthSource;
