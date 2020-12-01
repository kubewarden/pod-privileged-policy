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
    let config = new PolicyConfig("", ""); 

    let file = FileSystem.open("assembly/__tests__/fixtures/req_not_a_pod.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept requests that are neither CREATE nor UPDATE", () => {
    let config = new PolicyConfig("", ""); 

    let file = FileSystem.open("assembly/__tests__/fixtures/req_delete.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept privileged containers from trusted users", () => {
    let config = new PolicyConfig("kubernetes-admin,alice", "trusted-users"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept privileged containers from a user who belongs to a trusted group", () => {
    let config = new PolicyConfig("alice", "trusted-users,system:masters"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept pod with privileged context from trusted users", () => {
    let config = new PolicyConfig("kubernetes-admin,alice", "trusted-users"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept pod with privileged context from a user who belongs to a trusted group", () => {
    let config = new PolicyConfig("alice", "trusted-users,system:masters"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });


  it("should accept pods that do not have privileged containers", () => {
    let config = new PolicyConfig("alice", "trusted-users"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/no_privileged_containers.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should deny pod with privileged security context from untrusted users", () => {
    let config = new PolicyConfig("bob", "tenantA"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/top_level_privileged_security_context.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(false);
    expect(res.message).toBe("User cannot schedule privileged containers");
  });

  it("should deny privileged containers from untrusted users", () => {
    let config = new PolicyConfig("bob", "tenantA"); 

    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;

    let rawRes = validate(config, rawReq);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(false);
    expect(res.message).toBe("User cannot schedule privileged containers");
  });

});

