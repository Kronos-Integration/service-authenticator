import jwt from "jsonwebtoken";
import { mergeAttributes, createAttributes } from "model-attributes";
import { Service } from "@kronos-integration/service";

/**
 * @typedef {Object} JWTResponse
 * @property {string} acess_token
 * @property {string} token_type always "Bearer"
 */

/**
 *
 */
export class ServiceAuthenticator extends Service {
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
            options: {
              attributes: {
                algorithm: { default: "RS256", type: "string" },
                expiresIn: { default: "12h", type: "duration" }
              }
            }
          }
        }
      })
    );
  }

  static get description() {
    return "provide authentication services";
  }

  static get endpoints() {
    return {
      ...super.endpoints,
      access_token: {
        in: true,
        receive: "accessTokenGenerator"
      }
    };
  }

  entitlementFilter(e) {
    return e;
  }

  /**
   * Generate a request handler to deliver JWT access tokens
   * @param {Object} credentials
   * @param {string} credentials.username
   * @param {string} credentials.password
   * @return {JWTResponse} jwt
   */
  async accessTokenGenerator(credentials) {
    try {
      let entitlements = [];

      for (const e of this.outEndpoints) {
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
          access_token: jwt.sign(
            { entitlements: entitlements.join(",") },
            this.jwt.private,
            this.jwt.options
          )
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
