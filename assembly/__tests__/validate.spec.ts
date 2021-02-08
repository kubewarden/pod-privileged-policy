import { validate } from "../validate";
import { PolicyConfig } from "../policy_config";
import { FileSystem, Descriptor } from "as-wasi";
import { JSON } from "assemblyscript-json";

class ValidationResponse {
  accepted: bool;
  message: string;

  constructor(rawJson: string) {
    let req = JSON.parse(rawJson) as JSON.Obj;
    let accepted = req.get("accepted") as JSON.Bool;
    this.accepted = accepted._bool;

    if (req.has("message")) {
      let msg = req.get("message") as JSON.Str;
      this.message = msg._str;
    } else {
      this.message = "";
    }
  }
}

describe("validate", () => {

  it("should accept requests that are not about Pod resources", () => {
    let rawSettings = `{}`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/req_not_a_pod.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept requests that are neither CREATE nor UPDATE", () => {
    let rawSettings = `{}`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/req_delete.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept privileged containers from trusted users", () => {
    let rawSettings = `{
      "trusted_users": ["kubernetes-admin", "alice"],
      "trusted_groups": ["trusted-users"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept privileged containers from a user who belongs to a trusted group", () => {
    let rawSettings = `{
      "trusted_users": ["alice"],
      "trusted_groups": ["trusted-users", "system:masters"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept pod with privileged context from trusted users", () => {
    let rawSettings = `{
      "trusted_users": ["kubernetes-admin", "alice"],
      "trusted_groups": ["trusted-users"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept pod with privileged context from a user who belongs to a trusted group", () => {
    let rawSettings = `{
      "trusted_users": ["alice"],
      "trusted_groups": ["trusted-users", "system:masters"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });


  it("should accept pods that do not have privileged containers", () => {
    let rawSettings = `{
      "trusted_users": ["alice"],
      "trusted_groups": ["trusted-users"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/no_privileged_containers.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should deny pod with privileged security context from untrusted users", () => {
    let rawSettings = `{
      "trusted_users": ["bob"],
      "trusted_groups": ["tenantA"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(false);
    expect(res.message).toBe("User cannot schedule privileged containers");
  });

  it("should deny privileged containers from untrusted users", () => {
    let rawSettings = `{
      "trusted_users": ["bob"],
      "trusted_groups": ["tenantA"]
    }`;
    let settings = JSON.parse(rawSettings) as JSON.Obj;
    let config = new PolicyConfig(settings);

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(config, req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(false);
    expect(res.message).toBe("User cannot schedule privileged containers");
  });

});

