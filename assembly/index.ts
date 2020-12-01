import "wasi";
import { PolicyConfig } from "./policy_config";
import { validate } from "./validate";
import { Console, Environ } from "as-wasi"

function initConfig(): PolicyConfig {
  let env = new Environ();
  let trustedUsers = env.get("TRUSTED_USERS");
  if (trustedUsers == null) {
    trustedUsers = "";
  }

  let trustedGroups = env.get("TRUSTED_GROUPS");
  if (trustedGroups == null) {
    trustedGroups = "";
  }
  return new PolicyConfig(trustedUsers!, trustedGroups!);
}

let config = initConfig();
let request = Console.readAll()!;

Console.log(validate(config, request));