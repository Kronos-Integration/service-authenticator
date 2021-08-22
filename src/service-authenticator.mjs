import { promisify } from "util";
import jwt from "jsonwebtoken";
import ms from "ms";
import { mergeAttributes, createAttributes } from "model-attributes";
import { Service } from "@kronos-integration/service";

export const verifyJWT = promisify(jwt.verify);

/**
 * @typedef {Object} JWTResponse
 * @property {string} access_token
 * @property {string} refresh_token
 * @property {string} token_type always "Bearer"
 * @property {number} expires seconds the access token is valid
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
    const algorithm = { default: "RS256", type: "string" };

    return mergeAttributes(
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
            claims: {
              attributes: {
                iss: { type: "string" },
                aud: { type: "string" }
              }
            },
            access_token: {
              attributes: {
                algorithm,
                expiresIn: { default: "1h", type: "duration" }
              }
            },
            refresh_token: {
              attributes: {
                algorithm,
                expiresIn: { default: "90d", type: "duration" }
              }
            }
          }
        }
      }),
      Service.configurationAttributes
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
      let refreshClaims = { sequence: 1 };
    
      if (credentials.refresh_token) {
        const decoded = await verifyJWT(credentials.refresh_token, this.jwt.public);
        if (decoded) {
        //  this.info("refresh " + decoded);
          entitlements = ["refresh"]; // TODO
          refreshClaims.name = decoded.name;
          refreshClaims.sequence = decoded.sequence + 1;
        }
      }
      else {
        refreshClaims.name = credentials.username;

        for (const e of this.authEndpoints) {
          const response = await e.send(credentials);

          if (response && response.entitlements) {
            entitlements = [...response.entitlements];
            break;
          }
        }
      }

      entitlements = [...entitlements].filter(e => this.entitlementFilter(e));

      if (entitlements.length > 0) {
        const j = this.jwt;

        const claims = {
          name: credentials.username,
          ...j.claims,
          entitlements: entitlements.join(",")
        };
        return {
          token_type: "Bearer",
          expires_in: ms(j.access_token.expiresIn) / 1000,
          access_token: jwt.sign(claims, j.private, j.access_token),
          refresh_token: jwt.sign(refreshClaims, j.private, j.refresh_token)
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
