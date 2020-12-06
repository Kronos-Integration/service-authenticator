import jwt from "jsonwebtoken";
import { mergeAttributes, createAttributes } from "model-attributes";
import { Service } from "@kronos-integration/service";

/**
 * @typedef {Object} JWTResponse
 * @property {string} access_token
 * @property {string} refresh_token
 * @property {string} token_type always "Bearer"
 */

/**
 *
 */
export class ServiceAuthenticator extends Service {
  /**
   * @return {string} 'authenticator'
   */
  static get name() {
    return "authenticator";
  }

  static get description() {
    return "provide authentication services";
  }

  static get configurationAttributes() {
    return mergeAttributes(
      Service.configurationAttributes,
      createAttributes({
        jwt: {
          description: "jwt related",
          attributes: {
            private: {
              description: "private key for token",
              mandatory: true,
              private: true,
              type: "blob"
            },
            public: {
              description: "public key for token",
              mandatory: true,
              private: true,
              type: "blob"
            },
            access_token: {
              attributes: {
                algorithm: { default: "RS256", type: "string" },
                expiresIn: { default: "1h", type: "duration" }
              }
            },
            refresh_token: {
              attributes: {
                algorithm: { default: "RS256", type: "string" },
                expiresIn: { default: "30d", type: "duration" }
              }
            }
          }
        }
      })
    );
  }

  static get endpoints() {
    return {
      ...super.endpoints,
      change_password: {
        in: true,
        receive: "changePassword"
      },
      access_token: {
        in: true,
        receive: "accessTokenGenerator"
      }
    };
  }

  /**
   * Endpoints used to send password change requests to.
   */
  get changePasswordEndpoints() {
    return this.outEndpoints.filter(e => e.name.endsWith("change_password"));
  }

  /**
   * Endpoints used to send authentication requests to.
   */
  get authEndpoints() {
    return this.outEndpoints.filter(e => e.name.endsWith("authenticate"));
  }

  entitlementFilter(e) {
    return e;
  }

  async changePassword(request) {
    this.info(request);

    for (const e of this.changePasswordEndpoints) {
      response = await e.send(request);
    }

    return response;
  }

  /**
   * Generate a request handler to deliver JWT access tokens.
   * @param {Object} credentials
   * @param {string} credentials.username
   * @param {string} credentials.password
   * @return {JWTResponse} jwt
   */
  async accessTokenGenerator(credentials) {
    try {
      let entitlements = [];

      for (const e of this.authEndpoints) {
        const response = await e.send(credentials);

        if (response && response.entitlements) {
          entitlements = [...response.entitlements];
          break;
        }
      }

      entitlements = [...entitlements].filter(e => this.entitlementFilter(e));

      if (entitlements.length > 0) {
        return {
          token_type: "Bearer",
          expires_in: this.jwt.access_token.expiresIn,
          access_token: jwt.sign(
            { entitlements: entitlements.join(",") },
            this.jwt.private,
            this.jwt.access_token
          ),
          refresh_token: jwt.sign({}, this.jwt.private, this.jwt.refresh_token)
        };
      } else {
        throw new Error("Not authorized");
      }
    } catch (e) {
      this.error(e);
      throw new Error("Authentication failed");
    }
  }
}

export default ServiceAuthenticator;
