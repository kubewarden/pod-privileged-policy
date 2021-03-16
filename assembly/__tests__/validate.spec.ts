import { validate } from "../validate";
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
    let file = FileSystem.open("assembly/__tests__/fixtures/req_not_a_pod.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should accept requests that are neither CREATE nor UPDATE", () => {
    let file = FileSystem.open("assembly/__tests__/fixtures/req_delete.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

  it("should reject pods with privileged containers", () => {
    let file = FileSystem.open("assembly/__tests__/fixtures/privileged_container.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(false);
  });

  it("should accept pods that do not have privileged containers", () => {
    let file = FileSystem.open("assembly/__tests__/fixtures/no_privileged_containers.json", "r")!;
    let rawReq = file.readString()!;
    let req = JSON.parse(rawReq) as JSON.Obj;

    let rawRes = validate(req);
    let res = new ValidationResponse(rawRes);

    expect(res.accepted).toBe(true);
  });

});

