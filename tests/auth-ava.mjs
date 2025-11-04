import test from "ava";
import { readFileSync } from "node:fs";
import AuthSource from "./helpers/auth-source.mjs";
import { StandaloneServiceProvider } from "@kronos-integration/service";
import { ServiceAuthenticator } from "@kronos-integration/service-authenticator";

const config = {
  auth: {
    type: ServiceAuthenticator,
    endpoints: {
      "ldap.authenticate": "service(ldap).authenticate"
    },
    jwt: {
      public: readFileSync(
        new URL("fixtures/demo.rsa.pub", import.meta.url).pathname
      ),
      private: readFileSync(
        new URL("fixtures/demo.rsa", import.meta.url).pathname
      ),
      claims: {
        iss: "myself",
        aud: "all"
      }
    }
  },
  ldap: {
    type: AuthSource
  }
};

test("service-auth credentials", async t => {
  const sp = new StandaloneServiceProvider();
  const { auth } = await sp.declareServices(config);

  t.is(auth.description, "provide authentication services");
  t.true(
    auth.endpoints["ldap.authenticate"].isConnected(
      sp.services.ldap.endpoints.authenticate
    )
  );

  const response = await auth.endpoints.access_token.receive({
    username: "user1",
    password: "test"
  });
  t.is(response.token_type, "Bearer");
  t.is(response.expires_in, 1);
  const access_token = response.access_token;
  const data = JSON.parse(Buffer.from(access_token.split(".")[1], "base64"));
  t.deepEqual(data.entitlements.split(/,/), ["a", "b"]);
  t.is(data.iss, "myself");
  t.is(data.aud, "all");
  t.is(data.name, "user1");

  const refresh_token = response.refresh_token;
  t.truthy(refresh_token);
});

test("service-auth with refresh_token", async t => {
  const sp = new StandaloneServiceProvider();
  const { auth } = await sp.declareServices(config);

  let response = await auth.endpoints.access_token.receive({
    username: "user1",
    password: "test"
  });

  let refresh_token = response.refresh_token;
  let data = JSON.parse(Buffer.from(refresh_token.split(".")[1], "base64"));
  t.is(data.sequence, 1);

  response = await auth.endpoints.access_token.receive({
    refresh_token
  });

  refresh_token = response.refresh_token;
  data = JSON.parse(Buffer.from(refresh_token.split(".")[1], "base64"));
  t.is(data.sequence, 2);
  //t.is(data.name, "user1");
});
