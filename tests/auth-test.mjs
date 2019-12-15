import test from "ava";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import AuthSource from "./auth-source.mjs";

import { StandaloneServiceProvider } from "@kronos-integration/service";
import { ServiceAuthenticator } from "../src/service-authenticator.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const config = {
  auth: {
    type: ServiceAuthenticator,
    endpoints: {
      ldap: "service(ldap).authenticate"
    },
    jwt: {
      public: readFileSync(join(here, "fixtures", "demo.rsa.pub")),
      private: readFileSync(join(here, "fixtures", "demo.rsa"))
    }
  },
  ldap: {
    type: AuthSource
  }
};

test("service-auth", async t => {
  const sp = new StandaloneServiceProvider();
  const [auth] = await sp.declareServices(config);
  await auth.start();

  /*
  t.log(auth.endpoints.access_token);
  t.true(auth.endpoints.access_token.isConnected(sp.services.ldap.endpoints.authenticate));
  t.is(auth.state, "running");
*/

  const response = await auth.endpoints.access_token.receive({
    username: "user1",
    password: "test"
  });

  // t.is(response.username, 'user1');
  const access_token = response.access_token;
  const data = JSON.parse(Buffer.from(access_token.split(".")[1], "base64"));

  console.log(data);
  t.deepEqual(data.entitlements.split(/,/), ["a", "b"]);
});
